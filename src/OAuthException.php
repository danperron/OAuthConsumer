<?php
namespace danperron\OAuth;

/**
 * Description of OAuthException
 *
 * @author Dan Perron <danp3rr0n@gmail.com>
 */
class OAuthException extends \Exception {
    public function __construct($message, $code = 0, $previous = null) {
        parent::__construct($message, $code, $previous);
    }
}
