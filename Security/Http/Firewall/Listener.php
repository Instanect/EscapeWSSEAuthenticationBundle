<?php

namespace Escape\WSSEAuthenticationBundle\Security\Http\Firewall;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class Listener implements ListenerInterface
{
    /**
     * @var string WSSE header
     */
    private $wsseHeader;

    /**
     * @var TokenStorageInterface
     */
    protected $tokenStorage;

    /**
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * @var string Uniquely identifies the secured area
     */
    protected $providerKey;

    /**
     * @var AuthenticationEntryPointInterface
     */
    protected $authenticationEntryPoint;

    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthenticationManagerInterface $authenticationManager,
        $providerKey,
        AuthenticationEntryPointInterface $authenticationEntryPoint
    )
    {
        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey = $providerKey;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
    }

    /**
     * @param GetResponseEvent $event
     * @throws \InvalidArgumentException
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        //find out if the current request contains any information by which the user might be authenticated
        if (!$request->headers->has('X-WSSE')) {
            return;
        }

        $ae_message = null;
        $this->wsseHeader = $request->headers->get('X-WSSE');

        ini_set("log_errors", "On");
        ini_set("display_errors", "Off");
        error_reporting(E_ALL);
        error_log($this->wsseHeader);

        $wsseHeaderInfo = $this->parseHeader();

        if ($wsseHeaderInfo !== false) {
            $token = new Token(
                $wsseHeaderInfo['Username'],
                $wsseHeaderInfo['Password'],
                $this->providerKey
            );

            //     $token->setAttribute('nonce', $wsseHeaderInfo['Nonce']);
            //    $token->setAttribute('created', $wsseHeaderInfo['Created']);

            if (isset($wsseHeaderInfo['isRaw']))
                $token->setAttribute('is_raw', true);


            try {
                $returnValue = $this->authenticationManager->authenticate($token);

                if ($returnValue instanceof TokenInterface) {
                    return $this->tokenStorage->setToken($returnValue);
                } else
                    if ($returnValue instanceof Response) {
                        return $event->setResponse($returnValue);
                    }
            } catch (AuthenticationException $ae) {
                $event->setResponse($this->authenticationEntryPoint->start($request, $ae));
            }
        }
    }

    /**
     * This method returns the value of a bit header by the key
     *
     * @param $key
     * @return mixed
     * @throws \UnexpectedValueException
     */
    private function parseValue($key)
    {
        return preg_match('/' . $key . '="([^"]+)"/', $this->wsseHeader, $matches) ? $matches[1] : false;

    }

    /**
     * This method parses the X-WSSE header
     *
     * If Username, PasswordDigest, Nonce and Created exist then it returns their value,
     * otherwise the method returns false.
     *
     * @return array|bool
     */
    private function parseHeader()
    {
        $result = array();

        $result['Username'] = $this->parseValue('Username');
        $result['Password'] = $this->parseValue('Password');

        $isRaw = $this->parseValue('isRaw');
        if ($isRaw == true)
            $result['isRaw'] = true;

        return $this->checkResult($result);
    }

    public function checkResult($result)
    {
        return !(empty($result['Username'])
            || empty($result['Password'])) ? $result : false;
    }
}
