require 'logstash/devutils/rspec/spec_helper'
require 'logstash/outputs/tcp'
require 'flores/pki'

describe LogStash::Outputs::Tcp do
  subject { described_class.new(config) }

  let(:config) {
    {
      'socket_addresses' => ["localhost:#{2000 + rand(3000)}", "127.0.0.1:#{2000 + rand(3000)}"]
    }
  }

  context 'when enabling SSL' do
    let(:config) {
      super.merge('ssl_enable' => true)
    }

    context 'and not providing a certificate/key pair' do
      it 'registers without error' do
        expect { subject.register }.to_not raise_error
      end
    end

    context 'and providing a certificate/key pair' do
      let(:cert_key_pair) { Flores::PKI.generate }

      let(:certificate) { cert_key_pair.first }

      let(:cert_file) do
        path = Tempfile.new.path
        IO.write(path, certificate.to_s)
        path
      end

      let(:config) {
        super.merge('ssl_enable' => true, 'ssl_cert' => cert_file)
      }

      it 'registers without error' do
        expect { subject.register }.to_not raise_error
      end
    end
  end
end
