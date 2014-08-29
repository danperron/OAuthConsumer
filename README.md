#OAuth 1.0 Consumer for PHP
   

##Usage


###Obtaining and authenticating a request token

```php
<?php
/**
 * authenticate.php
 */
require_once './vendor/autoload.php';

use danperron\OAuth\OAuthConsumer;
use danperron\OAuth\OAuthException;

session_start();

$consumerKey = '{YOUR_CONSUMER_KEY}';
$consumerSecret = '{YOUR_CONSUMER_SECRET}';

//create a new OAuthConsumer
$oauthConsumer = new OAuthConsumer($consumerKey, $consumerSecret);

$oauthConsumer->setRequestTokenUrl('https://api.twitter.com/oauth/request_token');
$oauthConsumer->setAccessTokenUrl('https://api.twitter.com/oauth/access_token');
$oauthConsumer->setAuthorizeUrl('https://api.twitter.com/oauth/authorize');
$oauthConsumer->setCallbackUrl('{URL to callback.php}');

try {
    //Fetch request token
    $requestToken = $oauthConsumer->fetchRequestToken();
    
    //Add the consumer and the request token to the session
    $_SESSION['oauthConsumer'] = $oauthConsumer;
    $_SESSION['requestToken'] = $requestToken;
    
    //Authorize request token will perform a redirect
    $oauthConsumer->authorizeToken($requestToken);
    
} catch (OAuthException $e) {
    echo $e->getTraceAsString();
}
```

###Authenticating a request token

```php
<?php
/**
 * callback.php
 */
require_once './vendor/autoload.php';

use danperron\OAuth\OAuthConsumer;
use danperron\OAuth\OAuthException;
use danperron\OAuth\OAuthToken;

session_start();

//Retrieve OAuthConsumer from session
$oauthConsumer = $_SESSION['oauthConsumer'];
/* @var $oauthConsumer OAuthConsumer */

//Retrieve request token from session
$requestToken = $_SESSION['requestToken'];
/* @var $requestToken OAuthToken */
try {
    //Trade in newly authorized request token for an access token
    $accessToken = $oauthConsumer->fetchAccessToken($requestToken, array('oauth_verifier' => $_GET['oauth_verifier']));

    //Set the token on the oauth consumer
    $oauthConsumer->setToken($accessToken);

    //Request Twitter timeline and print
    $statuses = $oauthConsumer->makeRequest('https://api.twitter.com/1.1/statuses/home_timeline.json', OAuthConsumer::METHOD_GET);
    echo "Statuses:";
    var_dump(json_decode($statuses));
} catch (OAuthException $e) {
    echo $e->getTraceAsString();
}
```