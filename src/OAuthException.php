<?php
namespace danperron\OAuth;

/**
 * OAuthException
 *
 * @author Dan Perron <danp3rr0n@gmail.com>
 * @license http://opensource.org/licenses/MIT The MIT License (MIT)
 */
class OAuthException extends \Exception {
    public function __construct($message, $code = 0, $previous = null) {
        parent::__construct($message, $code, $previous);
    }
}
