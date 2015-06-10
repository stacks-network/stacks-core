require 'json'
require 'net/https'

class Client

	def initialize(key_id, key_secret)
       @key_id = key_id   
       @key_secret = key_secret  
       @base_url = "https://api.onename.com/v1"
    end 

  	def get_user(username)
  		url = @base_url + "/users/" +  username
  		return send_request(url)
	end

	def get_search(query)
		url = @base_url + "/search?query=" + query
		return send_request(url)
	end

	def get_stats()
		url = @base_url + "/users"
		return send_request(url)
	end

	def get_address(address)
		url = @base_url + "/addresses/" + address
		return send_request(url)
	end

    def send_request(url)

    	uri = URI(url)

		Net::HTTP.start(uri.host, uri.port,
	    :use_ssl => uri.scheme == 'https', 
	    :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|

		 	request = Net::HTTP::Get.new uri.request_uri
		 	request.basic_auth @key_id, @key_secret
	 		response = http.request request 
	 	
			return response.body
		end

    end
end
