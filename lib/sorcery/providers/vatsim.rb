module Sorcery
  module Providers
    class Vatsim < Base
      include Protocols::Oauth

      attr_accessor :access_token_path, :authorize_path, :request_token_path, :site


      def initialize
        @site        = ''
        @configuration = {
            authorize_path: '/auth/pre_login',
            request_token_path: '/api/login_token',
            access_token_path: '/api/login_return',
            signature_method: 'RSA-SHA1',
            scheme: :body
        }
      end

      def get_consumer
        @configuration[:site] = @site
        OAuth::Consumer.new(@key, OpenSSL::PKey::RSA.new(@secret),@configuration)
      end


      def get_user_hash(access_token)
        r = JSON.parse(access_token.params.keys.first.to_s)
        {}.tap do |h|
          h[:user_info] = r['user']
          h[:uid] = h[:user_info]['id'].to_s
        end
      end

      # calculates and returns the url to which the user should be redirected,
      # to get authenticated at the external provider's site.
      def login_url(params, session)
        req_token = get_request_token
        h = JSON.parse(req_token.params.keys.first.to_s)
        session[:request_token] = h['token']['oauth_token']
        session[:request_token_secret] = h['token']['oauth_token_secret']
        authorize_url({request_token: h['token']['oauth_token'], request_token_secret: h['token']['oauth_token_secret']})
      end

      # tries to login the user from access token
      def process_callback(params, session)
        args = {
            oauth_verifier: params[:oauth_verifier],
            request_token: session[:request_token],
            request_token_secret: session[:request_token_secret]
        }
        get_access_token(args)
      end

    end
  end
end
