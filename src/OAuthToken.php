<?php
namespace danperron\OAuth;
/**
 * Object representation of an OAuth token.  
 *
 * @author Dan Perron <danp3rr0n@gmail.com>
 * @license http://opensource.org/licenses/MIT The MIT License (MIT)
 */
class OAuthToken {
    private $tokenString = '';
    private $tokenSecret = '';
    
    /**
     * 
     * @param string $tokenString - the oauth token
     * @param string $tokenSecret - the token secret
     */
    function __construct($tokenString, $tokenSecret) {
        $this->tokenString = $tokenString;
        $this->tokenSecret = $tokenSecret;
    }

    /**
     * return the token string
     * 
     * @return string
     */
    public function getTokenString() {
        return $this->tokenString;
    }

    /**
     * return the token secret
     * 
     * @return string
     */
    public function getTokenSecret() {
        return $this->tokenSecret;
    }
    
    /**
     * Build token object from response string
     * 
     * @param string $responseString
     * @return \danperron\OAuth\OAuthToken
     * @throws OAuthException
     */
    public static function parseToken($responseString){
        
        $tokenParts = array();
        parse_str($responseString, $tokenParts);
        
        if(!array_key_exists('oauth_token', $tokenParts) || 
                !array_key_exists('oauth_token_secret', $tokenParts)){
            throw new OAuthException("Unable to parse token response.");
        }

        return new OAuthToken($tokenParts['oauth_token'], $tokenParts['oauth_token_secret']);
    }   
}