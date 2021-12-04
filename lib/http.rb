# frozen_string_literal: true

module Kenna
  module 128iid
    module Helpers
      module Http
        def http_get(url, headers, max_retries = 5, verify_ssl = true)
          RestClient::Request.execute(
            method: :get,
            url: url,
            headers: headers,
            verify_ssl: verify_ssl
          )
        rescue RestClient::TooManyRequests => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            sleep(15)
            puts "Retrying!"
            retry
          end
        rescue RestClient::UnprocessableEntity => e
          puts "Exception! #{e}"
        rescue RestClient::BadRequest => e
          puts "Exception! #{e}"
        rescue RestClient::InternalServerError => e
          retries ||= 0
          if retries < max_retries
            retries += 1
            sleep(15)
            puts "Retrying!"
            retry
          end
          puts "Exception! #{e}"
        rescue RestClient::ServerBrokeConnection => e
          puts "Exception! #{e}"
        rescue RestClient::ExceptionWithResponse => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            puts "Retrying!"
            sleep(15)
            retry
          end
        rescue RestClient::NotFound => e
          puts "Exception! #{e}"
        rescue RestClient::Exception => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            sleep(15)
            puts "Retrying!"
            retry
          end
        rescue Errno::ECONNREFUSED => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            puts "Retrying!"
            sleep(15)
            retry
          end
        end

        def http_post(url, headers, payload, max_retries = 5, verify_ssl = true)
          RestClient::Request.execute(
            method: :post,
            url: url,
            payload: payload,
            headers: headers,
            verify_ssl: verify_ssl
          )
        rescue RestClient::TooManyRequests => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            puts "Retrying!"
            sleep(15)
            retry
          end
        rescue RestClient::UnprocessableEntity => e
          puts "Exception! #{e}"
        rescue RestClient::BadRequest => e
          puts "Exception! #{e}"
        rescue RestClient::InternalServerError => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            puts "Retrying!"
            sleep(15)
            retry
          end
        rescue RestClient::ServerBrokeConnection => e
          puts "Exception! #{e}"
        rescue RestClient::ExceptionWithResponse => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            puts "Retrying!"
            sleep(15)
            retry
          end
        rescue RestClient::NotFound => e
          puts "Exception! #{e}"
        rescue RestClient::Exception => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            puts "Retrying!"
            sleep(15)
            retry
          end
        rescue Errno::ECONNREFUSED => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            puts "Retrying!"
            sleep(15)
            retry
          end
        end
      end
    end
  end
end
