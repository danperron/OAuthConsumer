<?php
namespace danperron\OAuth;
/**
 * Description of OAuthToken
 *
 * @author Dan Perron <danp3rr0n@gmail.com>
 */
class OAuthToken {
    private $tokenString = '';
    private $tokenSecret = '';
    
    
    function __construct($tokenString, $tokenSecret) {
        $this->tokenString = $tokenString;
        $this->tokenSecret = $tokenSecret;
    }

    public function getTokenString() {
        return $this->tokenString;
    }

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
