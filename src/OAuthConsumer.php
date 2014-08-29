<?php

namespace danperron\OAuth;

use Exception;

/**
 * OAuthConsumer - A simple OAuth 1.0 Consumer class
 *
 * @author Dan Perron <danp3rr0n@gmail.com>
 * 
 * @license http://opensource.org/licenses/MIT The MIT License (MIT)
 * 
 */
class OAuthConsumer {

    /**
     * The Consumer key given by the OAuth provider
     * 
     * @var string 
     */
    private $consumerKey = '';
    
    /**
     * The consumer secret given by the OAuth provider
     * 
     * @var string
     */
    private $consumerSecret = '';
    
    
    /**
     * The currently set access token.
     * 
     * @var OAuthToken
     */
    private $token = null;
    
    /**
     * The location to retrieve request tokens.
     * 
     * @var string
     */
    private $requestTokenUrl = '';
    
    /**
     * The location to retrieve access tokens
     * 
     * @var string 
     */
    private $accessTokenUrl = '';
    
    /**
     * The authorization url for authorizing request tokens.
     * 
     * @var string 
     */
    private $authorizeUrl = '';
    
    /**
     * Callback url to be sent with the authorization request.
     * 
     * @var string
     */
    private $callbackUrl = '';
    
    /**
     * last timestamp generated
     * 
     * @var int
     */
    private $lastTimeStamp;
    
    /**
     * last nonce generated
     * 
     * @var string 
     */
    private $lastNonce;

    const SIGNATURE_METHOD = 'HMAC-SHA1';
    const OAUTH_VERSION = '1.0';
    
    const METHOD_GET = 'GET';
    const METHOD_POST = 'POST';
    const METHOD_PUT = 'PUT';
    const METHOD_DELETE = 'DELETE';
    const METHOD_HEAD = 'HEAD';

    /**
     * 
     * 
     * @param string $consumerKey - The consumer key given by the OAuth provider
     * @param string $consumerSecret - The consumer secret given by the OAuth provider
     */
    function __construct($consumerKey, $consumerSecret) {
        $this->consumerKey = $consumerKey;
        $this->consumerSecret = $consumerSecret;
    }

    /**
     * Fetch a request token.
     * 
     * @param array $params
     * @return OAuthToken
     * @throws OAuthException
     */
    public function fetchRequestToken($params = array()) {

        $this->lastTimeStamp = time();
        $this->lastNonce = self::generateNonce();
        
        $requestParams = array(
            'oauth_timestamp' => $this->lastTimeStamp,
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_signature_method' => self::SIGNATURE_METHOD,
            'oauth_signature' => $this->generateSignature($this->generateBaseString($this->requestTokenUrl, self::METHOD_POST, $params)),
            'oauth_nonce' => $this->lastNonce,
            'oauth_version' => self::OAUTH_VERSION
        );

        $requestParams = array_merge($requestParams, $params);

        try {
            $response = $this->makeCall($this->requestTokenUrl, self::METHOD_POST, $params, $this->generateHeader($requestParams));

            $requestToken = OAuthToken::parseToken($response);

            return $requestToken;
        } catch (OAuthException $e) {
            throw $e;
        } catch (Exception $e) {
            throw new OAuthException("Unable to fetch request token.", 0, $e);
        }
    }

    /**
     * 
     * Attemp to fetch an access token from an authorized request token.
     * 
     * @param OAuthToken $authorizedRequestToken
     * @param array $params
     * @return OAuthToken
     * @throws OAuthException
     */
    public function fetchAccessToken(OAuthToken $authorizedRequestToken, $params = array()) {
        
        $this->lastNonce = self::generateNonce();
        $this->lastTimeStamp = time();
        
        $requestParams = array(
            'oauth_timestamp' => $this->lastTimeStamp,
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_token' => $authorizedRequestToken->getTokenString(), 
            'oauth_signature_method' => self::SIGNATURE_METHOD,
            'oauth_signature' => $this->generateSignature(
                    $this->generateBaseString($this->accessTokenUrl, self::METHOD_POST), $authorizedRequestToken),
            'oauth_nonce' => $this->lastNonce,
            'oauth_version' => self::OAUTH_VERSION
        );

        $requestParams = array_merge($requestParams, $params);

        try {
            $response = $this->makeCall($this->accessTokenUrl, self::METHOD_POST, $params, $this->generateHeader($requestParams));
            
            $accessToken = OAuthToken::parseToken($response);
            $this->token =  $accessToken;
            return $accessToken;
        } catch (OAuthException $e) {
            throw $e;
        } catch(Exception $e){
            throw new OAuthException('Unable to fetch access token.', 0, $e);
        }
    }
    
    /**
     * generate oauth authorization header
     * 
     * @param array $params
     * @return string
     */
    private function generateHeader($params){
        $requiredKeys = array(
            'oauth_timestamp', 
            'oauth_consumer_key', 
            'oauth_signature_method', 
            'oauth_signature',
            'oauth_callback',
            'oauth_nonce',
            'oauth_verifier',
            'oauth_token', 
            'oauth_version'
        );
        
        $paramArray = array_intersect_key($params, array_flip($requiredKeys));
        
        $header = 'Authorization: OAuth ';
        $valuePairs = array();
        foreach($paramArray as $key => $value){
            array_push($valuePairs, $key.'="'.self::urlEncode($value).'"');
        }
        
        $header .= implode(',', $valuePairs);
        return $header;
    }
    
    /**
     * Make an authorized request with a valid access token.
     * 
     * @param string $url - url to be called
     * @param string $method - http method to use
     * @param array $parameters - an array of parameters to be sent
     * @return string - the returned response body
     * @throws OAuthException
     */
    public function makeRequest($url, $method, $parameters = array()){
         
        $this->lastNonce = self::generateNonce();
        $this->lastTimeStamp = time();
        
        $requestParams = array(
            'oauth_timestamp' => $this->lastTimeStamp,
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_signature_method' => self::SIGNATURE_METHOD,
            'oauth_signature' => $this->generateSignature(
                    $this->generateBaseString($url, $method), $this->token),
            'oauth_nonce' => $this->lastNonce,
            'oauth_version' => self::OAUTH_VERSION
        );
         
        if($this->token != null){
            $requestParams['oauth_token'] = $this->token->getTokenString();
        }
         
        $requestParams = array_merge($requestParams, $parameters);
        
        return $this->makeCall($url, $method, $parameters, $this->generateHeader($requestParams));
    }

    /**
     * redirect to authorize url with request token
     * 
     * @param OAuthToken $requestToken
     */
    public function authorizeToken(OAuthToken $requestToken) {
        $queryParams = array(
            'oauth_token' => $requestToken->getTokenString()
        );

        if (!empty($this->callbackUrl)) {
            $queryParams['oauth_callback'] = $this->callbackUrl;
        }

        $location = $this->authorizeUrl . '?' . http_build_query($queryParams);
        header("Location: $location");
    }

    /**
     * Generate oauth_signature from base string and token if available
     * 
     * @param string $baseString
     * @param OAuthToken $token
     * @return string
     */
    private function generateSignature($baseString, OAuthToken $token = null) {
        $key = self::urlEncode($this->consumerSecret) . '&';
        if ($token != null) {
            $key .= self::urlEncode($token->getTokenSecret());
        }
        return base64_encode(hash_hmac('sha1', $baseString, $key, true));
    }
    
    /**
     * Generate the base string used to build the signature.
     * 
     * @param string $url
     * @param string $method
     * @param array $params
     * @return string
     */
    private function generateBaseString($url, $method, $params = array()) {
        $baseString = $method . '&' . self::urlEncode($url) . '&';

        $baseStringParams = array(
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_signature_method' => self::SIGNATURE_METHOD,
            'oauth_timestamp' => $this->lastTimeStamp,
            'oauth_nonce' => $this->lastNonce,
            'oauth_version' => self::OAUTH_VERSION
        );
        
        if($this->token != null){
            $baseStringParams['oauth_token'] = $this->token->getTokenString();
        }

        $baseStringParams = array_merge($baseStringParams, $params);

        ksort($baseStringParams);

        $valuePairs = array();
        foreach ($baseStringParams as $key => $value) {
            array_push($valuePairs, $key . '=' . self::urlEncode($value));
        }

        $baseString .= self::urlEncode(implode('&', $valuePairs));
        return $baseString;
    }

    /**
     * Generate a random nonce
     * 
     * @return type
     */
    private static function generateNonce() {
        return md5(microtime() . mt_rand());
    }

    /**
     * Url encode
     * 
     * @param string $string
     * @return string
     */
    private static function urlEncode($string) {
        return str_replace(array('%7E', '+'), array('~', ' '), rawurlencode($string));
    }

    /**
     * Set the request token url
     * 
     * @param string $requestTokenUrl
     */
    public function setRequestTokenUrl($requestTokenUrl) {
        $this->requestTokenUrl = $requestTokenUrl;
    }

    /**
     * set the access token url
     * 
     * @param string $accessTokenUrl
     */
    public function setAccessTokenUrl($accessTokenUrl) {
        $this->accessTokenUrl = $accessTokenUrl;
    }

    /**
     * set the authorize url
     * 
     * @param string $authorizeUrl
     */
    public function setAuthorizeUrl($authorizeUrl) {
        $this->authorizeUrl = $authorizeUrl;
    }

    /**
     * set the callback url.  This callback may not be the one that is called
     * if there is a callback url set at the OAuth provider.
     * 
     * @param string $callbackUrl
     */
    public function setCallbackUrl($callbackUrl) {
        $this->callbackUrl = $callbackUrl;
    }

    /**
     * returns the currently set access token
     * 
     * @return OAuthToken
     */
    public function getToken() {
        return $this->token;
    }

    /**
     * Set an oauth access token to be used to make calls
     * 
     * @param OAuthToken $token
     */
    public function setToken(OAuthToken $token) {
        $this->token = $token;
    }

    /**
     * make http call
     * 
     * @param string $url
     * @param string $method
     * @param array $parameters
     * @param string $header
     * @return string
     * @throws OAuthException
     */
    private function makeCall($url, $method, $parameters = array(), $header) {
        $ch = curl_init();
        
        switch ($method){
            case self::METHOD_GET:
                $url = $url . '?' . http_build_query($parameters);
                break;
            case self::METHOD_POST:
                curl_setopt($ch, CURLOPT_POST, 1);
                if(count($parameters) > 0){
                    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($parameters));
                }
                break;
            case self::METHOD_PUT:
                curl_setopt($ch, CURLOPT_PUT, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($parameters));
                break;
            case self::METHOD_DELETE:
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, self::METHOD_DELETE);
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($parameters));
                break;
            default:
                throw new OAuthException("Unsupported method $method");
        }
        
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array($header));

        $response = curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);
        
        $http_code = $info['http_code'];
        
        if($http_code > 400){
            throw new OAuthException("Server returned error message: $response", $http_code);
        }
        
        return $response;
    }

}
