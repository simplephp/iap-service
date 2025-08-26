<?php

namespace Simplephp\IapService\Provider;

use Exception;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Simplephp\IapService\Abstracts\APayment;
use Simplephp\IapService\Contracts\INotify;
use Simplephp\IapService\Exception\VerificationException;
use Simplephp\IapService\Model\NotificationPayload;
use Simplephp\IapService\Util\JWT;
use Simplephp\IapService\Util\Request;
use Simplephp\IapService\Util\Response;

/**
 * Class Huawei
 * @package Simplephp\IapService\Provider
 */
class Huawei extends APayment
{
    /**
     * 服务商名称
     */
    const SP_NAME = 'huawei';

    /**
     * @var string $environment 当前环境
     */
    private $environment;

    /**
     * 正式环境
     * @var string
     */
    const PRODUCTION_URL = 'https://iap.cloud.huawei.com';

    /**
     * @var Request
     */
    private $client = null;
    /**
     * @var string $kid 密钥标识符
     */
    private $kid;
    /**
     * @var string APP ID，获取方式参见:https://developer.huawei.com/consumer/cn/doc/harmonyos-guides-V5/iap-config-app-identity-info-V5
     */
    private $aid;
    /**
     * @var string $issuerId 服务商标识符
     */
    private $issuerId;
    /**
     * @var string $algorithm 算法
     */
    private $algorithm = 'ES256';
    /**
     * @var string $leafCertOid 证书OID
     */
    private $leafCertOid;

    /**
     * @var string $privateKeyPath 私钥路径
     */
    private $privateKeyPath;

    /**
     * @var float $timeout 超时时间
     */
    private $timeout = 10.0;
    /**
     * @var false|mixed
     */
    private $retryEnabled = false;
    /**
     * @var int|mixed
     */
    private $maxRetryAttempts = 3;
    /**
     * @var int[]|mixed
     */
    private $retryOnStatus = [429, 500];
    /**
     * @var JWT
     */
    private $jwtService;

    /**
     * @var string aud
     */
    const JWT_PLAYLOAD_AUD = 'iap-v1';

    /**
     * @var string exp
     */
    const JWT_PLAYLOAD_EXP = 3600;

    /**
     * 订单状态查询（消耗型/非消耗型商品）
     * /order/harmony/v1/application/order/status/query
     * @link https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/iap-query-order-status-V5
     */
    const QUERY_ORDER_STATUS = '/order/harmony/v1/application/order/status/query';

    /**
     * 订单确认发货（消耗型/非消耗型商品）
     * /order/harmony/v1/application/purchase/shipped/confirm
     * @link https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/iap-confirm-purchase-for-order-V5
     */
    const CONFIRM_PURCHASE_FOR_ORDER = '/order/harmony/v1/application/purchase/shipped/confirm';

    /**
     * 订阅状态查询
     * /subscription/harmony/v1/application/subscription/status/query
     * @link https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/iap-query-subscription-status-V5
     */
    const QUERY_SUBSCRIPTION_STATUS = '/subscription/harmony/v1/application/subscription/status/query';

    /**
     * 订阅确认发货
     * /subscription/harmony/v1/application/purchase/shipped/confirm
     * @link https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/iap-confirm-purchase-for-sub-V5
     */
    const CONFIRM_PURCHASE_FOR_SUBSCRIPTION = '/subscription/harmony/v1/application/purchase/shipped/confirm';

    /**
     * @var array $config 配置
     */
    private $config;

    /**
     * @param $config
     * @param string $environment
     * @throws \Exception
     */
    public function __construct($config, string $environment = self::ENV_PRODUCTION)
    {
        $this->environment = $environment;
        $this->config = $config;
        $this->initialization($config);
    }

    /**
     * @param $config
     * @return void
     */
    public function initialization($config)
    {
        $this->config = $config;
        $this->leafCertOid = $config['leaf_cert_oid'] ?? '';
        $this->kid = $config['kid'] ?? '';
        $this->aid = $config['aid'] ?? '';
        $this->issuerId = $config['issuer_id'] ?? '';
        $this->algorithm = $config['algorithm'] ?? $this->algorithm;
        $this->privateKeyPath = $config['private_key_path'] ?? '';
        // 网络请求设置
        $this->timeout = $config['timeout'] ?? $this->timeout;
        $this->retryEnabled = $options['retry_enabled'] ?? $this->retryEnabled;
        $this->maxRetryAttempts = $options['max_retry_attempts'] ?? $this->maxRetryAttempts;
        $this->retryOnStatus = $options['retry_on_status'] ?? $this->retryOnStatus;
        $this->client = Request::factory([
            'base_uri' => $this->getRequestBaseURL(),
            'headers' => [
                'Content-Type' => 'application/json;charset=UTF-8',
            ],
            'timeout' => $this->timeout,
            // 开启 retry 重试
            'retry_enabled' => true,
            'max_retry_attempts' => $this->maxRetryAttempts,
            // 开启 jwt 验证
            'jwt_enable' => true,
            'private_key_path' => $this->privateKeyPath,
            'jwtHeader' => $this->getJwtHeader(),
            'jwtPayload' => $this->getJwtPayload(),
        ]);
        $this->jwtService = new JWT([
            'unsafeMode' => false,
            'algorithm' => JWT::ALGORITHM_ES256['name'],
            'leafCertOid' => $this->leafCertOid,
        ]);
    }

    /**
     * 订单状态查询（消耗型/非消耗型商品）
     * @link https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/iap-query-order-status-V5
     * @param $purchaseOrderId
     * @param $purchaseToken
     * @param array $options
     * @return Response
     * @throws GuzzleException
     * @throws VerificationException
     */
    public function orderStatus($purchaseOrderId, $purchaseToken, array $options = []): Response
    {
        try {
            if (empty($purchaseOrderId)) {
                throw new InvalidArgumentException('purchaseOrderId不能为空');
            }
            if (empty($purchaseToken)) {
                throw new InvalidArgumentException('purchaseToken不能为空');
            }
            $response = $this->client->post(self::QUERY_ORDER_STATUS, [
                'json' => [
                    'purchaseOrderId' => $purchaseOrderId,
                    'purchaseToken' => $purchaseToken,
                ],
            ], $options);
            $content = $response->getBody()->getContents();
            $result = json_decode($content, true);
            if (!isset($result['responseCode'])) {
                return Response::error(-1, 'responseCode不存在');
            }
            if ($result['responseCode'] != 0) {
                $msg = $result['responseMessage'] ?? '未知错误';
                return Response::error($result['responseCode'], $msg);
            } else {
                if (isset($result['jwsPurchaseOrder']) && !empty($result['jwsPurchaseOrder'])) {
                    $result['jwsPurchaseOrder'] = $this->getJwtService()->decodedSignedData($result['jwsPurchaseOrder']);
                } else {
                    $result['jwsPurchaseOrder'] = [];
                }
                return Response::success($result);
            }
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 订单确认发货（消耗型/非消耗型商品）
     * /order/harmony/v1/application/purchase/shipped/confirm
     * @link https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/iap-confirm-purchase-for-order-V5
     * @param $purchaseOrderId
     * @param $purchaseToken
     * @param array $options
     * @return Response
     * @throws Exception
     * @throws GuzzleException
     * @throws InvalidArgumentException
     */
    public function confirmOrder($purchaseOrderId, $purchaseToken, array $options = []): Response
    {
        try {
            if (empty($purchaseOrderId)) {
                throw new InvalidArgumentException('purchaseOrderId不能为空');
            }
            if (empty($purchaseToken)) {
                throw new InvalidArgumentException('purchaseToken不能为空');
            }
            $response = $this->client->post(self::CONFIRM_PURCHASE_FOR_ORDER, [
                'json' => [
                    'purchaseOrderId' => $purchaseOrderId,
                    'purchaseToken' => $purchaseToken,
                ],
            ], $options);
            $content = $response->getBody()->getContents();
            $result = json_decode($content, true);
            if (!isset($result['responseCode'])) {
                return Response::error(-1, 'responseCode不存在');
            }
            if ($result['responseCode'] != 0) {
                $msg = $result['responseMessage'] ?? '未知错误';
                return Response::error($result['responseCode'], $msg);
            } else {
                return Response::success($result);
            }
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 订阅状态查询
     * /subscription/harmony/v1/application/subscription/status/query
     * @link https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/iap-query-subscription-status-V5
     * @link https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/iap-query-subscription-status-V5#section149821246171719
     * @param $purchaseOrderId
     * @param $purchaseToken
     * @param array $options
     * @return Response
     * @throws GuzzleException
     * @throws VerificationException
     */
    public function subscriptionStatus($purchaseOrderId, $purchaseToken, array $options = []): Response
    {
        try {
            if (empty($purchaseOrderId)) {
                throw new InvalidArgumentException('purchaseOrderId不能为空');
            }
            if (empty($purchaseToken)) {
                throw new InvalidArgumentException('purchaseToken不能为空');
            }
            $response = $this->client->post(self::QUERY_SUBSCRIPTION_STATUS, [
                'json' => [
                    'purchaseOrderId' => $purchaseOrderId,
                    'purchaseToken' => $purchaseToken,
                ],
            ], $options);
            $content = $response->getBody()->getContents();
            $result = json_decode($content, true);
            if (!isset($result['responseCode'])) {
                return Response::error(-1, 'responseCode不存在');
            }
            if ($result['responseCode'] != 0) {
                $msg = $result['responseMessage'] ?? '未知错误';
                return Response::error($result['responseCode'], $msg);
            } else {
                if (isset($result['jwsSubGroupStatus']) && !empty($result['jwsSubGroupStatus'])) {
                    $result['jwsSubGroupStatus'] = $this->getJwtService()->decodedSignedData($result['jwsSubGroupStatus']);
                } else {
                    $result['jwsSubGroupStatus'] = [];
                }
                return Response::success($result);
            }
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 订阅确认发货
     * /subscription/harmony/v1/application/subscription/shipped/confirm
     * @link https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/iap-confirm-purchase-for-sub-V5
     * @param $purchaseOrderId
     * @param $purchaseToken
     * @param array $options
     * @return Response
     * @throws Exception
     * @throws GuzzleException
     * @throws InvalidArgumentException
     */
    public function confirmSubscription($purchaseOrderId, $purchaseToken, array $options = []): Response
    {
        try {
            if (empty($purchaseOrderId)) {
                throw new InvalidArgumentException('purchaseOrderId不能为空');
            }
            if (empty($purchaseToken)) {
                throw new InvalidArgumentException('purchaseToken不能为空');
            }
            $response = $this->client->post(self::CONFIRM_PURCHASE_FOR_SUBSCRIPTION, [
                'json' => [
                    'purchaseOrderId' => $purchaseOrderId,
                    'purchaseToken' => $purchaseToken,
                ],
            ], $options);
            $content = $response->getBody()->getContents();
            $result = json_decode($content, true);
            if (!isset($result['responseCode'])) {
                return Response::error(-1, 'responseCode不存在');
            }
            if ($result['responseCode'] != 0) {
                $msg = $result['responseMessage'] ?? '未知错误';
                return Response::error($result['responseCode'], $msg);
            } else {
                return Response::success($result);
            }
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * @return void
     */
    public function notify()
    {
        try {
            $result = $this->notifyWithResult();
            exit(Response::notify($result));
        } catch (\Exception $e) {
            exit(Response::notify(false));
        }
    }

    /**
     * @return mixed
     */
    public function notifyWithResult()
    {
        $notifyData = $this->getNotifyData();
        if (empty($notifyData)) {
            throw new \InvalidArgumentException('异步通知数据为空');
        }
        if (!isset($notifyData['jwsNotification'])) {
            throw new \InvalidArgumentException('JWS数据不存在');
        }
        if (!is_string($notifyData['jwsNotification'])) {
            throw new \InvalidArgumentException('JWS数据格式错误');
        }
        $this->payloadData = $this->getJwtService()->decodedSignedData($notifyData['jwsNotification']);
        $notificationType = $this->payloadData['notificationType'] ?? '';
        $subtype = $this->payloadData['notificationSubtype'] ?? '';
        $notifyCallback = $this->getServerNotify($notificationType, $subtype);
        if (!($notifyCallback instanceof INotify)) {
            throw new \InvalidArgumentException('未找到对应的通知处理器');
        }
        return $notifyCallback->handle(self::SP_NAME, $this->payloadData);
    }

    /**
     * @return JWT
     */
    public function getJwtService(): JWT
    {
        return $this->jwtService;
    }

    /**
     * 获取JWT header 数据
     * @return array
     */
    private function getJwtHeader(): array
    {
        return [
            JWT::HEADER_ALG => $this->algorithm,
            JWT::HEADER_KID => $this->kid,
            JWT::TYPE => 'JWT',
        ];
    }

    /**
     * 获取JWT payload 数据
     * @return array
     */
    public function getJwtPayload(): array
    {
        return [
            JWT::PAYLOAD_ISS => $this->issuerId,
            JWT::PAYLOAD_AUD => self::JWT_PLAYLOAD_AUD,
            JWT::PAYLOAD_IAT => time(),
            JWT::PAYLOAD_EXP => time() + self::JWT_PLAYLOAD_EXP,
            'aid' => $this->aid,
            'digest' => function (RequestInterface $request) {
                $jsonData = $request->getBody()->getContents();
                return hash('sha256', $jsonData);
            },
        ];
    }

    /**
     * @return string
     */
    public function getRequestBaseURL(): string
    {
        return self::PRODUCTION_URL;
    }
}