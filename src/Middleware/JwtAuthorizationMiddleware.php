<?php

namespace Simplephp\IapService\Middleware;

use Closure;
use Firebase\JWT\JWT;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;

use function call_user_func;

/* @phpstan-ignore-line */

use function is_callable;

class JwtAuthorizationMiddleware
{
    /**
     * @var callable
     */
    private $nextHandler;

    /**
     * JWT_HEADER
     */
    const JWT_HEADER = 'Authorization';

    /**
     * JWT_HEADER_PREFIX
     */
    const JWT_HEADER_PREFIX = 'Bearer ';

    /**
     * @var array<string,mixed>
     */
    private $defaultOptions = [
        // 开启 jwt 验证
        'jwt_enable' => true,
        'private_key_path' => null,
        'jwtHeader' => [],
        'jwtPayload' => [],
    ];

    /**
     * @param array $defaultOptions
     * @return Closure
     */
    public static function factory(array $defaultOptions = []): Closure
    {
        return function (callable $handler) use ($defaultOptions): self {
            return new static($handler, $defaultOptions);
        };
    }

    /**
     * GuzzleRetryMiddleware constructor.
     *
     * @param callable $nextHandler
     * @param array $defaultOptions
     */
    final public function __construct(callable $nextHandler, array $defaultOptions = [])
    {
        $this->nextHandler = $nextHandler;
        $this->defaultOptions = array_replace($this->defaultOptions, $defaultOptions);
    }

    /**
     * @param RequestInterface $request
     * @param array<string,mixed> $options
     * @return Closure
     */
    public function __invoke(RequestInterface $request, array $options): PromiseInterface
    {
        $handler = $this->nextHandler;
        $options = array_replace($this->defaultOptions, $options);
        $jwtEnable = $options['jwt_enable'] ?? false;
        if (false === $jwtEnable) {
            return $handler($request, $options);
        }
        // digest callable function
        if (!isset($options['jwtHeader'])) {
            throw new \InvalidArgumentException('Invalid jwtHeader');
        }
        $alg = $options['jwtHeader']['alg'] ?? null;
        if (is_null($alg)) {
            throw new \InvalidArgumentException('Invalid alg value');
        }
        foreach ($options['jwtHeader'] as $key => $value) {
            if (is_callable($value)) {
                $options['jwtHeader'][$key] = call_user_func($value, $request);
            }
        }
        // private_key_path
        if (!isset($options['private_key_path'])) {
            throw new \InvalidArgumentException('Invalid private key path');
        }
        // check if file exists, 私钥证书文件不存在
        if (!file_exists($options['private_key_path'])) {
            throw new \InvalidArgumentException('Private key certificate file does not exist');
        }
        // check if file is readable
        if (!is_readable($options['private_key_path'])) {
            throw new \InvalidArgumentException('Private key certificate file is not readable');
        }
        // digest callable function
        if (!isset($options['jwtPayload'])) {
            throw new \InvalidArgumentException('Invalid jwtPayload');
        }
        foreach ($options['jwtPayload'] as $key => $value) {
            if (is_callable($value)) {
                $options['jwtPayload'][$key] = call_user_func($value, $request);
            }
        }
        $privateKeyResource = file_get_contents($options['private_key_path']);
        $this->checkPrivateKey($privateKeyResource);
        $jwtValue = self::JWT_HEADER_PREFIX . $this->generateToken($privateKeyResource, $options['jwtHeader'], $options['jwtPayload']);
        $request = $request->withHeader(self::JWT_HEADER, $jwtValue);
        return $handler($request, $options);
    }

    /**
     * @param string $privateKeyResource
     * @param array $jwtHeader
     * @param array $jwtPayload
     * @return string
     */
    public function generateToken(string $privateKeyResource, array $jwtHeader, array $jwtPayload): string
    {
        $kid = $jwtHeader['kid'] ?? null;
        $alg = $jwtHeader['alg'] ?? null;
        return JWT::encode($jwtPayload, $privateKeyResource, $alg, $kid, $jwtHeader);
    }

    /**
     * @param $privateKeyResource
     * @return void
     */
    protected function checkPrivateKey($privateKeyResource)
    {
        $resource = openssl_pkey_get_private($privateKeyResource);
        if ($resource === false) {
            throw new \InvalidArgumentException('Private key certificate error');
        }

        if (version_compare(PHP_VERSION, '8.0.0', '<') && function_exists('openssl_free_key')) {
            openssl_free_key($resource);
        }
    }
}