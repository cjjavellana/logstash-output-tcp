# encoding: utf-8
require 'logstash/outputs/base'
require 'logstash/namespace'
require 'logstash/util/socket_peer'

# Write events over a TCP socket.
#
# Each event json is separated by a newline.
#
# Can either accept connections from clients or connect to a server,
# depending on `mode`.
class LogStash::Outputs::Tcp < LogStash::Outputs::Base

  config_name 'tcp'
  concurrency :single

  default :codec, 'json'

  # When mode is `server`, the address to listen on.
  # Listens on the first address it successfully binds to
  #
  # When mode is `client`, the address to connect to.
  # Connects to the first address it successfully opened a connection to.
  # If it encounters TCP errors while sending payload, it failovers
  # to the next configured address
  #
  # Format: <hostname>:<port>, <ip>:<port>
  config :socket_addresses, validate: :array, required: true

  # When connect failed,retry interval in sec.
  config :reconnect_interval, validate: :number, default: 10

  # Mode to operate in. `server` listens for client connections,
  # `client` connects to a server.
  config :mode, validate: %w(server client), default: 'client'

  # Enable SSL (must be set for other `ssl_` options to take effect).
  config :ssl_enable, validate: :boolean, default: false

  # Verify the identity of the other end of the SSL connection against the CA.
  # For input, sets the field `sslsubject` to that of the client certificate.
  config :ssl_verify, validate: :boolean, default: false

  # The SSL CA certificate, chainfile or CA path. The system CA path is
  # automatically included.
  config :ssl_cacert, validate: :path

  # SSL certificate path
  config :ssl_cert, validate: :path

  # SSL key path
  config :ssl_key, validate: :path

  # SSL key passphrase
  config :ssl_key_passphrase, validate: :password, default: nil

  class Client

    def initialize(socket, logger)
      @socket = socket
      @logger = logger
      @queue = Queue.new
    end

    def run
      loop do
        begin
          @socket.write(@queue.pop)
        rescue StandardError => e
          @logger.warn('tcp output exception', socket: @socket, exception: e)
          break
        end
      end
    end


    public

    def write(msg)
      @queue.push(msg)
    end
  end

  def initialize(config)
    @socket_address_index = 0
    @ssl_cert = false
    @ssl_key = nil
    @ssl_verify = false
    @ssl_cacert = nil
    @ssl_enable = false
    @socket_addresses = []
    @reconnect_interval = 10

    super(config)
  end

  private

  def setup_ssl
    require 'openssl'

    @ssl_context = OpenSSL::SSL::SSLContext.new
    if @ssl_cert
      @ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(@ssl_cert))
      if @ssl_key
        @ssl_context.key = OpenSSL::PKey::RSA.new(File.read(@ssl_key), @ssl_key_passphrase)
      end
    end

    return unless @ssl_verify

    ssl_verify
  end

  def ssl_verify
    @cert_store = OpenSSL::X509::Store.new
    # Load the system default certificate path to the store
    @cert_store.set_default_paths
    if File.directory?(@ssl_cacert)
      @cert_store.add_path(@ssl_cacert)
    else
      @cert_store.add_file(@ssl_cacert)
    end
    @ssl_context.cert_store = @cert_store
    @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
  end

  public

  def register
    require 'socket'
    require 'stud/try'

    setup_ssl if @ssl_enable

    if server?
      @server_socket = server_socket

      if @ssl_enable
        @server_socket = OpenSSL::SSL::SSLServer.new @server_socket, @ssl_context
      end
      @client_threads = []

      @accept_thread = Thread.new(@server_socket) do |server_socket|
        loop do
          Thread.start(server_socket.accept) do |client_socket|
            # monkeypatch a 'peer' method onto the socket.
            client_socket.instance_eval {
              class << self;
                include ::LogStash::Util::SocketPeer
              end
            }
            @logger.debug('Accepted connection',
                          client: client_socket.peer,
                          server: "#{@socket_addresses[@socket_address_index]}")

            client = Client.new(client_socket, @logger)
            Thread.current[:client] = client
            @client_threads << Thread.current
            client.run
          end
        end
      end

      @codec.on_event do |event, payload|
        @client_threads.each do |client_thread|
          client_thread[:client].write(payload)
        end
        @client_threads.reject! { |t| !t.alive? }
      end
    else
      @logger.info("Client Socket Address #{@socket_addresses}")

      client_socket = nil
      @codec.on_event do |event, payload|
        begin
          client_socket ||= connect
          r, w, e = IO.select([client_socket], [client_socket], [client_socket], nil)
          # don't expect any reads, but a readable socket might
          # mean the remote end closed, so read it and throw it away.
          # we'll get an EOFError if it happens.
          client_socket.sysread(16_384) if r.any?

          # Now send the payload
          client_socket.syswrite(payload) if w.any?
        rescue StandardError => e
          @logger.warn('tcp output exception',
                       address: @socket_addresses[@socket_address_index],
                       exception: e,
                       backtrace: e.backtrace)

          client_socket.close rescue nil
          client_socket = nil

          sleep @reconnect_interval
          retry
        end
      end
    end
  end

  # def register

  private

  def server_socket
    while @socket_address_index < @socket_addresses.length
      begin
        @logger.info('Starting tcp output listener',
                     address: "#{@socket_addresses[@socket_address_index]}")

        socket_address = @socket_addresses[@socket_address_index].split(':')
        return TCPServer.new(socket_address[0], socket_address[1].to_i)
      rescue Errno::EADDRINUSE
        @logger.error('Could not start TCP server: Address in use', address: @socket_addresses[@socket_address_index])
        next_socket_address
      end
    end
    raise 'Exhausted all socket address options'
  end

  def next_socket_address
    @socket_address_index += 1
    return unless @socket_address_index >= @socket_addresses.length

    @socket_address_index = 0
  end

  def connect
    Stud.try do
      @socket_address_index = 0

      begin
        socket_address = @socket_addresses[@socket_address_index].split(':')

        @logger.info("Connecting to #{socket_address[0]} #{socket_address[1].to_i}")
        client_socket = TCPSocket.new(socket_address[0], socket_address[1].to_i)

        if @ssl_enable
          client_socket = OpenSSL::SSL::SSLSocket.new(client_socket, @ssl_context)
          begin
            client_socket.connect
          rescue OpenSSL::SSL::SSLError => ssle
            @logger.error('SSL Error', exception: ssle, backtrace: ssle.backtrace)
            # NOTE(mrichar1): Hack to prevent hammering peer
            sleep(5)
            raise
          end
        end

        client_socket.instance_eval {
          class << self;
            include ::LogStash::Util::SocketPeer
          end
        }

        @logger.debug('Opened connection', client: "#{client_socket.peer}")
        return client_socket
      rescue StandardError => e
        @socket_address_index += 1

        raise e if @socket_address_index >= @socket_addresses.length

        retry
      end
    end
  end

  def server?
    @mode == 'server'
  end

  public

  def receive(event)
    @codec.encode(event)
  end
end
