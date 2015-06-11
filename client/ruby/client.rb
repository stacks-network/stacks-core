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
  		return get_request(url)
	end

	def get_search(query)
		url = @base_url + "/search?query=" + query
		return get_request(url)
	end

	def get_stats()
		url = @base_url + "/users"
		return get_request(url)
	end

	def get_address(address)
		url = @base_url + "/addresses/" + address
		return get_request(url)
	end

	def register_user(payload)
		# payload = {'passname' => 'randomguy', 'recipient_address' => '1LvmdgWbrBtjLYiFs5d8ukTz2Z5Ksccrv8',
		# 					'passcard' => {'bio' => 'I am a random guy who thinks!'}} 

		url = @base_url + "/users"
		return post_request(url, payload)
	end

	def broadcast_transaction(payload)
		#payload = {"signed_hex" => "00710000015e98119922f0b"}

		url = @base_url +  "/transactions"
		return post_request(url, payload)
	end

    def get_request(url)

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

	def post_request(url, payload)
		
		uri = URI.parse(url)
		http = Net::HTTP.new(uri.host, uri.port)
		http.use_ssl = true
		http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		request = Net::HTTP::Post.new(uri.request_uri,initheader = {'Content-Type' =>'application/json'})
		request.body = payload.to_json
		
		request.basic_auth @key_id, @key_secret
		response = http.request(request)
		return response.body


    end

end
