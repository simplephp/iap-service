<?php

namespace Simplephp\IapService\Provider;

use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use InvalidArgumentException;
use Simplephp\IapService\Abstracts\APayment;
use Simplephp\IapService\Contracts\INotify;
use Simplephp\IapService\Exception\VerificationException;
use Simplephp\IapService\Util\JWT;
use Simplephp\IapService\Util\Request;
use Simplephp\IapService\Util\Response;

/**
 * Class Apple
 * @package Simplephp\IapService\Provider
 */
class Apple extends APayment
{
    /**
     * 服务商名称
     */
    const SP_NAME = 'apple';

    /**
     * @var string $environment 当前环境
     */
    private $environment;

    /**
     * 正式环境
     * @var string
     */
    const PRODUCTION_URL = 'https://api.storekit.itunes.apple.com';

    /**
     * 沙箱环境
     * @var string
     */
    const SANDBOX_URL = 'https://api.storekit-sandbox.itunes.apple.com';

    /**
     * @var Request
     */
    private $client = null;
    /**
     * @var string $kid 密钥标识符
     */
    private $kid;
    /**
     * @var string $bundleId 应用程序的标识符
     */
    private $bundleId;
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
    const JWT_PLAYLOAD_AUD = 'appstoreconnect-v1';

    /**
     * @var string exp
     */
    const JWT_PLAYLOAD_EXP = 3600;

    /**
     * 获取应用程序单笔交易信息
     * /inApps/v1/transactions/{transactionId}|{(originalTransactionId}
     * @link https://developer.apple.com/documentation/appstoreserverapi/get_transaction_info
     */
    const QUERY_TRANSACTION = '/inApps/v1/transactions/%s';

    /**
     * 应用程序中获取客户所有自动续订订阅的状态（Get All Subscription Statuses）
     * /inApps/v1/subscriptions/{transactionId}
     * @link https://developer.apple.com/documentation/appstoreserverapi/get_all_subscription_statuses
     */
    const QUERY_ALL_SUBSCRIPTIONS = '/inApps/v1/subscriptions/%s';

    /**
     * 通过订单 ID 获取客户在应用内购买记录
     * /inApps/v1/lookup/{orderId}
     * @link https://developer.apple.com/documentation/appstoreserverapi/look_up_order_id
     */
    const LOOKUP_URI = '/inApps/v1/lookup/%s';

    /**
     * 查询用户历史收据 直接上V2, V1已经废了
     * https://developer.apple.com/documentation/appstoreserverapi/get_transaction_history
     * /inApps/v2/history/{originalTransactionId}
     */
    const QUERY_HISTORY = '/inApps/v2/history/%s';

    /**
     * 查询用户内购退款
     * https://developer.apple.com/documentation/appstoreserverapi/get_refund_history
     * /inApps/v2/refund/lookup/{transactionId}
     */
    const QUERY_REFUND = '/inApps/v2/refund/lookup/%s';

    /**
     * 延长用户订阅的时长
     * @link https://developer.apple.com/documentation/appstoreserverapi/extend_a_subscription_renewal_date
     * {PUT} /inApps/v1/subscriptions/extend/{originalTransactionId}
     */
    const EXTEND_SUBSCRIPTION = '/inApps/v1/subscriptions/extend/%s';

    /**
     * 延长符合条件的用户的续订日期
     * @link https://developer.apple.com/documentation/appstoreserverapi/extend_subscription_renewal_dates_for_all_active_subscribers
     * {POST} /inApps/v1/subscriptions/extend/{originalTransactionId}
     */
    const EXTEND_SUBSCRIPTION_MASS = '/inApps/v1/subscriptions/extend/mass/';

    /**
     * 提交防欺诈信息，当用户申请退款时，苹果通知（CONSUMPTION_REQUEST）开发者服务器，开发者可在12小时内，提供用户的信息（比如游戏金币是否已消费、用户充值过多少钱、退款过多少钱等），最后苹果收到这些信息，协助“退款决策系统” 来决定是否允许用户退款。
     * @link https://developer.apple.com/documentation/appstoreserverapi/send_consumption_information
     */
    const SEND_CONSUMPTION_INFORMATION = '/inApps/v1/transactions/consumption/%s';

    /**
     * 测试 App Store 服务器通知
     * @link https://developer.apple.com/documentation/appstoreserverapi/request_a_test_notification
     */
    const NOTIFICATIONS_TEST = '/inApps/v1/notifications/test';

    /**
     * @link https://developer.apple.com/documentation/appstoreserverapi/request_a_test_notification
     * 测试 App Store 服务器通知状态
     */
    const NOTIFICATIONS_STATUS = '/inApps/v1/notifications/test/%s';

    /**
     * 活动通知历史
     * @link  https://developer.apple.com/documentation/appstoreserverapi/get_notification_history
     */
    const NOTIFICATIONS_HISTORY = '/inApps/v1/notifications/history';


    /**
     * @param $config
     * @param string $environment
     * @throws \Exception
     */
    public function __construct($config, string $environment = self::ENV_PRODUCTION)
    {
        if ($environment != self::ENV_PRODUCTION && $environment != self::ENV_SANDBOX) {
            throw new InvalidArgumentException('Environmental parameter error');
        }
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
        $this->bundleId = $config['bundle_id'] ?? '';
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
                'Content-Type' => 'application/json',
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
     * 获取交易信息
     * @link https://developer.apple.com/documentation/appstoreserverapi/get_transaction_info
     * @param string $transactionId
     * @param array $options
     * @return Response
     * @throws GuzzleException
     * @throws VerificationException
     */
    public function transactions(string $transactionId, array $options = []): Response
    {
        try {
            if (empty($transactionId)) {
                throw new InvalidArgumentException('transactionId 不能为空');
            }
            $url = $this->getFullRequestURL(self::QUERY_TRANSACTION, $transactionId);
            $response = $this->client->get($url, $options);
            $data = json_decode($response->getBody(), true);
            if (!isset($data['signedTransactionInfo'])) {
                return Response::success($data);
            }
            return Response::success($this->getJwtService()->decodedSignedData($data['signedTransactionInfo']));
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 通过订单编号获取交易信息
     * @link https://developer.apple.com/documentation/appstoreserverapi/look_up_order_id
     * @param string $orderId
     * @param array $options
     * @return Response
     * @throws GuzzleException
     * @throws VerificationException
     */
    public function lookup(string $orderId, array $options = []): Response
    {
        try {
            if (empty($orderId)) {
                throw new InvalidArgumentException('订单编号不能为空');
            }
            $url = $this->getFullRequestURL(self::LOOKUP_URI, $orderId);
            $response = $this->client->get($url, $options);
            $data = json_decode($response->getBody(), true);
            if (!empty($data['signedTransactions'])) {
                $results = [];
                foreach ($data['signedTransactions'] as $v) {
                    $payload = $this->getJwtService()->decodedSignedData($v);
                    $results[] = $payload;
                }
                $data['signedTransactions'] = $results;
            }
            return Response::success($data);
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 苹果IAP-通过originalTransactionId获取用户在APP内所有的订阅状态
     * @link https://developer.apple.com/documentation/appstoreserverapi/get_all_subscription_statuses
     * @param string $originalTransactionId
     * @param array $queryParameters
     * @param array $options
     * @return Response
     * @throws GuzzleException
     * @throws VerificationException
     */
    public function subscriptionStatuses(string $originalTransactionId, array $queryParameters = [], array $options = []): Response
    {
        try {
            if (empty($originalTransactionId)) {
                throw new InvalidArgumentException('originalTransactionId不能为空');
            }
            $url = $this->getFullRequestURL(self::QUERY_ALL_SUBSCRIPTIONS, $originalTransactionId);
            $response = $this->client->get($url, [
                'query' => $queryParameters,
            ], $options);
            $data = $response->getBody()->getContents();
            $dataX = json_decode($data, true);
            if (!empty($dataX['data'])) {
                foreach ($dataX['data'] as $k => $v) {
                    if (!empty($v['lastTransactions'])) {
                        foreach ($v['lastTransactions'] as $kk => $vv) {
                            $signedTransactionInfo = $this->getJwtService()->decodedSignedData($vv['signedTransactionInfo']);
                            $dataX['data'][$k]['lastTransactions'][$kk]['signedTransactionInfo'] = $signedTransactionInfo;
                            $signedRenewalInfo = $this->getJwtService()->decodedSignedData($vv['signedRenewalInfo']);
                            $dataX['data'][$k]['lastTransactions'][$kk]['signedRenewalInfo'] = $signedRenewalInfo;
                        }
                    }
                }
            }
            return Response::success($dataX);
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 通过transactionId/originalTransactionId获取用户在APP内所有的交易历史记录
     * @link https://developer.apple.com/documentation/appstoreserverapi/subscriptiongroupidentifier
     * @link 参数 https://developer.apple.com/documentation/appstoreserverapi/get_transaction_history#query-parameters
     * @param string $transactionId
     * @param array $queryParams
     * @param array $options
     * @return Response
     * @throws GuzzleException
     * @throws VerificationException
     */
    public function transactionHistory(string $transactionId, array $queryParams, array $options = []): Response
    {
        // transactionId 必须
        if (empty($transactionId)) {
            throw new InvalidArgumentException('transactionId 不能为空');
        }
        $query = [];
        // 其他查询参数 revision
        if (isset($queryParams['revision']) && !empty($queryParams['revision'])) {
            $query['revision'] = $queryParams['revision'];
        }
        // 查询参数：startDate UNIX 时间（以毫秒为单位）,13位时间戳
        if (!empty($queryParams['startDate'])) {
            if (!is_numeric($queryParams['startDate']) || strlen($queryParams['startDate']) != 13) {
                throw new InvalidArgumentException('startDate 必须是13位时间戳');
            }
            $query['startDate'] = $queryParams['startDate'];
        }
        // 查询参数：endDate UNIX 时间（以毫秒为单位）
        if (!empty($queryParams['endDate'])) {
            if (!is_numeric($queryParams['endDate']) || strlen($queryParams['endDate']) != 13) {
                throw new InvalidArgumentException('startDate 必须是13位时间戳');
            }
            $query['endDate'] = $queryParams['endDate'];
        }
        // 如果开始时间和结束时间都传递，则开始时间必须小于结束时间
        if (!empty($queryParams['startDate']) && !empty($queryParams['endDate'])) {
            if ($queryParams['startDate'] > $queryParams['endDate']) {
                throw new InvalidArgumentException('startDate 必须小于 endDate');
            }
        }
        // 查询参数：productId
        if (!empty($queryParams['productId'])) {
            $query['productId'] = $queryParams['productId'];
        }
        // 查询参数：productType， 可选值：AUTO_RENEWABLE, NON_RENEWABLE, CONSUMABLE, NON_CONSUMABLE
        if (!empty($queryParams['productType'])) {
            $query['productType'] = $queryParams['productType'];
        }
        // 查询参数：inAppOwnershipType，可选值：FAMILY_SHARED（该交易属于从服务中受益的家庭成员）, PURCHASED（该交易属于购买者）
        if (!empty($queryParams['inAppOwnershipType'])) {
            $query['inAppOwnershipType'] = $queryParams['inAppOwnershipType'];
        }
        // 查询参数：sort，可选值：ASCENDING, DESCENDING
        if (!empty($queryParams['sort'])) {
            if (!in_array($queryParams['sort'], ['ASCENDING', 'DESCENDING'])) {
                throw new InvalidArgumentException('sort 只能是 ASCENDING 或 DESCENDING');
            }
            $query['sort'] = $queryParams['sort'];
        }
        // 查询参数：revoked, 可选值：true, false
        if (!empty($queryParams['revoked'])) {
            if (!in_array($queryParams['revoked'], ['true', 'false'])) {
                throw new InvalidArgumentException('revoked 只能是 true 或 false字符串');
            }
            $query['revoked'] = $queryParams['revoked'];
        }
        //  查询参数：subscriptionGroupIdentifier
        if (!empty($queryParams['subscriptionGroupIdentifier'])) {
            $query['subscriptionGroupIdentifier'] = $queryParams['subscriptionGroupIdentifier'];
        }
        try {
            $url = $this->getFullRequestURL(self::QUERY_HISTORY, $transactionId);
            $response = $this->client->get($url, [
                'query' => $query
            ], $options);
            $data = json_decode($response->getBody(), true);
            if (!empty($data['signedTransactions'])) {
                $results = [];
                foreach ($data['signedTransactions'] as $v) {
                    $results[] = $this->getJwtService()->decodedSignedData($v);
                }
                $data['signedTransactions'] = $results;
            }
            return Response::success($data);
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 通过transactionId/originalTransactionId获取用户在APP内所有的退款历史记录
     * @link https://developer.apple.com/documentation/appstoreserverapi/get_refund_history
     * @param $transactionId
     * @param array $queryParams
     * @param array $options
     * @return Response
     * @throws GuzzleException
     * @throws VerificationException
     */
    public function refundHistory($transactionId, array $queryParams = [], array $options = []): Response
    {
        $query = [];
        if (isset($queryParams['revision']) && !empty($queryParams['revision'])) {
            $query['revision'] = $queryParams['revision'];
        }
        try {
            $url = $this->getFullRequestURL(self::QUERY_REFUND, $transactionId);
            $response = $this->client->get($url, [
                'query' => $query
            ], $options);
            $data = json_decode($response->getBody(), true);
            if (!empty($data['signedTransactions'])) {
                $results = [];
                foreach ($data['signedTransactions'] as $v) {
                    $results[] = $this->getJwtService()->decodedSignedData($v);
                }
                $data['signedTransactions'] = $results;
            }
            return Response::success($data);
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 通过originalTransactionId延长用户订阅有效期
     * @link https://developer.apple.com/documentation/appstoreserverapi/extend_a_subscription_renewal_date
     * {PUT} /inApps/v1/subscriptions/extend/{originalTransactionId}
     * @param $originalTransactionId
     * @param array $putParams
     * @param array $options
     * @return Response
     * @throws GuzzleException
     */
    public function extendSubscription($originalTransactionId, array $putParams = [], array $options = []): Response
    {
        $bodyParams = [];
        // 最大 90 天
        if (!isset($putParams['extendByDays'])) {
            throw new InvalidArgumentException('extendByDays 参数必须');
        }
        if (!is_numeric($putParams['extendByDays']) || $putParams['extendByDays'] < 1 || $putParams['extendByDays'] > 90) {
            throw new InvalidArgumentException('extendByDays 必须是 1-90 之间的数字');
        }
        $bodyParams['extendByDays'] = $putParams['extendByDays'];
        // extendReasonCode
        if (!isset($putParams['extendReasonCode'])) {
            throw new InvalidArgumentException('extendReasonCode 参数必须');
        }
        // // 0 未申报 1 让客户满意 2 其他原因 3 服务商问题或中断
        if (!in_array($putParams['extendReasonCode'], ['0', '1', '2', '3'])) {
            throw new InvalidArgumentException('extendReasonCode 只能是 0, 1, 2, 3');
        }
        $bodyParams['extendReasonCode'] = $putParams['extendReasonCode'];
        // requestIdentifier
        if (!isset($putParams['requestIdentifier'])) {
            throw new InvalidArgumentException('requestIdentifier 参数必须');
        }
        $bodyParams['requestIdentifier'] = $putParams['requestIdentifier'];
        try {
            $url = $this->getFullRequestURL(self::EXTEND_SUBSCRIPTION, $originalTransactionId);
            $response = $this->client->put($url, [
                'json' => $bodyParams
            ], $options);
            $data = json_decode($response->getBody(), true);
            return Response::success($data);
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 批量延长符合条件用户订阅有效期
     * @link https://developer.apple.com/documentation/appstoreserverapi/extend_subscription_renewal_dates_for_all_active_subscribers
     * @param array $postParams
     * @param array $options
     * @return Response
     * @throws GuzzleException
     */
    public function extendSubscriptionMass(array $postParams = [], array $options = []): Response
    {
        $bodyParams = [];
        // requestIdentifier
        if (!isset($postParams['requestIdentifier'])) {
            throw new InvalidArgumentException('requestIdentifier 参数必须');
        }
        $bodyParams['requestIdentifier'] = $postParams['requestIdentifier'];
        // 最大 90 天
        if (!isset($postParams['extendByDays'])) {
            throw new InvalidArgumentException('extendByDays 参数必须');
        }
        if (!is_numeric($postParams['extendByDays']) || $postParams['extendByDays'] < 1 || $postParams['extendByDays'] > 90) {
            throw new InvalidArgumentException('extendByDays 必须是 1-90 之间的数字');
        }
        $bodyParams['extendByDays'] = $postParams['extendByDays'];
        // extendReasonCode
        if (!isset($postParams['extendReasonCode'])) {
            throw new InvalidArgumentException('extendReasonCode 参数必须');
        }
        if (!in_array($postParams['extendReasonCode'], ['0', '1', '2', '3'])) {
            throw new InvalidArgumentException('extendReasonCode 只能是 0, 1, 2, 3');
        }
        $bodyParams['extendReasonCode'] = $postParams['extendReasonCode'];
        // extendReasonCode
        if (!isset($postParams['productId'])) {
            throw new InvalidArgumentException('productId 参数必须');
        }
        $bodyParams['productId'] = $postParams['productId'];
        // storefrontCountryCodes
        if (!isset($postParams['storefrontCountryCodes'])) {
            throw new InvalidArgumentException('storefrontCountryCodes 参数必须');
        }
        $bodyParams['storefrontCountryCodes'] = $postParams['storefrontCountryCodes'];
        try {
            $url = $this->getFullRequestURL(self::EXTEND_SUBSCRIPTION_MASS);
            $response = $this->client->put($url, [
                'json' => $bodyParams
            ], $options);
            $data = json_decode($response->getBody(), true);
            return Response::success($data);
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 防欺诈信息提交，当用户申请退款时，苹果通知（CONSUMPTION_REQUEST）开发者服务器，开发者可在12小时内，提供用户的信息（比如游戏金币是否已消费、用户充值过多少钱、退款过多少钱等），最后苹果收到这些信息，协助“退款决策系统” 来决定是否允许用户退款。
     * @link https://developer.apple.com/documentation/appstoreserverapi/get_refund_history
     * 参数讲解移步至：https://developer.apple.com/documentation/appstoreserverapi/consumptionrequest#properties
     * @param $originalTransactionId
     * @param array $putParams
     * @param array $options
     * @return Response
     * @throws GuzzleException
     */
    public function sendConsumptionInformation($originalTransactionId, array $putParams = [], array $options = []): Response
    {
        try {
            if (empty($putParams) || !is_array($putParams)) {
                throw new InvalidArgumentException('参数必须是一个数组');
            }
            $url = $this->getFullRequestURL(self::SEND_CONSUMPTION_INFORMATION, $originalTransactionId);
            $response = $this->client->put($url, [
                'json' => $putParams
            ], $options);
            $data = json_decode($response->getBody(), true);
            return Response::success($data);
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 获取APP Store 通知服务器向开发者发送的历史通知记录
     * @kink https://developer.apple.com/documentation/appstoreserverapi/get_notification_history
     * @param string $paginationToken
     * @param array $postParams
     * @param array $options
     * @return Response
     * @throws GuzzleException
     * @throws VerificationException
     */
    public function notificationHistory(string $paginationToken = '', array $postParams = [], array $options = []): Response
    {
        $body = [];
        // 查询参数：startDate UNIX 时间（以毫秒为单位）,13位时间戳 180内
        if (!empty($postParams['startDate'])) {
            if (!is_numeric($postParams['startDate']) || strlen($postParams['startDate']) != 13) {
                throw new InvalidArgumentException('startDate 必须是13位时间戳');
            }
            $body['startDate'] = $postParams['startDate'];
        }
        // 查询参数：endDate UNIX 时间（以毫秒为单位）
        if (!empty($postParams['endDate'])) {
            if (!is_numeric($postParams['endDate']) || strlen($postParams['endDate']) != 13) {
                throw new InvalidArgumentException('startDate 必须是13位时间戳');
            }
            $body['endDate'] = $postParams['endDate'];
        }
        // 如果开始时间和结束时间都传递，则开始时间必须小于结束时间
        if (!empty($postParams['startDate']) && !empty($postParams['endDate'])) {
            if ($postParams['startDate'] > $postParams['endDate']) {
                throw new InvalidArgumentException('startDate 必须小于 endDate');
            }
        }
        // notificationType 通知类型
        if (!empty($postParams['notificationType'])) {
            $body['notificationType'] = $postParams['notificationType'];
        }
        // onlyFailures
        if (!empty($postParams['onlyFailures'])) {
            if (!is_bool($postParams['onlyFailures'])) {
                throw new InvalidArgumentException('onlyFailures 必须是布尔值');
            }
            $body['onlyFailures'] = $postParams['onlyFailures'];
        }
        // transactionId
        if (!empty($postParams['transactionId'])) {
            $body['transactionId'] = $postParams['transactionId'];
        }
        // notificationType 和 transactionId 二选一不能同时存在
        if (!empty($postParams['notificationType']) && !empty($postParams['transactionId'])) {
            throw new InvalidArgumentException('notificationType 和 transactionId 二选一不能同时存在');
        }
        try {
            $postBody = [];
            if (!empty($paginationToken)) {
                $postBody['query'] = ['paginationToken' => $paginationToken];
            }
            $postBody['json'] = $body;
            $response = $this->client->post(self::NOTIFICATIONS_HISTORY, $postBody, $options);
            $data = json_decode($response->getBody(), true);
            if (!empty($data['notificationHistory'])) {
                foreach ($data['notificationHistory'] as $k => $v) {
                    $data['notificationHistory'][$k]['signedPayload'] = $this->getJwtService()->decodedSignedData($v['signedPayload']);
                }
            }
            return Response::success($data);
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * 苹果IAP-向App Store通知服务器发送测试通知到开发者服务器
     * @link https://developer.apple.com/documentation/appstoreserverapi/request_a_test_notification
     * @param string $notificationType
     * @param array $options
     * @return Response
     * @throws GuzzleException
     */
    public function notificationTest(string $notificationType, array $options = []): Response
    {
        /**
         * notificationType: 通知类型，可选值：
         * SUBSCRIBED
         * DID_CHANGE_RENEWAL_PREF
         * DID_CHANGE_RENEWAL_STATUS
         * OFFER_REDEEMED
         * DID_RENEW
         * EXPIRED
         * DID_FAIL_TO_RENEW
         * GRACE_PERIOD_EXPIRED
         * PRICE_INCREASE
         * REFUND
         * REFUND_DECLINED
         * CONSUMPTION_REQUEST
         * RENEWAL_EXTENDED
         * REVOKE
         * TEST
         * RENEWAL_EXTENSION
         * REFUND_REVERSED
         * EXTERNAL_PURCHASE_TOKEN
         * ONE_TIME_CHARGE
         */
        try {
            if (empty($notificationType)) {
                throw new InvalidArgumentException('notificationType 参数必须');
            }
            $response = $this->client->post($this->getFullRequestURL(self::NOTIFICATIONS_TEST), [
                'json' => [
                    'notificationType' => $notificationType,
                ]
            ], $options);
            $data = json_decode($response->getBody(), true);
            return Response::success($data);
        } catch (RequestException $e) {
            return Response::exception($e);
        }
    }

    /**
     * App Store 通知服务器向开发者服务器发送的测试通知结果检测
     * @link https://developer.apple.com/documentation/appstoreserverapi/get_test_notification_status
     * @param string $testNotificationToken
     * @param array $options
     * @return Response
     * @throws GuzzleException
     * @throws VerificationException
     */
    public function notificationStatus(string $testNotificationToken, array $options = []): Response
    {
        try {
            if (empty($testNotificationToken)) {
                throw new InvalidArgumentException('testNotificationToken 参数必须');
            }
            $response = $this->client->get($this->getFullRequestURL(self::NOTIFICATIONS_STATUS, $testNotificationToken), $options);
            $data = json_decode($response->getBody(), true);
            // signedPayload
            if (!empty($data['signedPayload'])) {
                $data['signedPayload'] = $this->getJwtService()->decodedSignedData($data['signedPayload']);
            }
            return Response::success($data);
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
        if (!isset($notifyData['signedPayload'])) {
            throw new \InvalidArgumentException('JWS数据不存在');
        }
        if (!is_string($notifyData['signedPayload'])) {
            throw new \InvalidArgumentException('JWS数据格式错误');
        }

        $this->payloadData = $this->getJwtService()->decodedSignedData($notifyData['signedPayload']);
        $notificationType = $this->payloadData['notificationType'] ?? '';
        $subtype = $this->payloadData['subtype'] ?? '';
        $notifyCallback = $this->getServerNotify($notificationType, $subtype);
        if (!($notifyCallback instanceof INotify)) {
            throw new \InvalidArgumentException('未找到对应的通知处理器');
        }
        // 如果存在payload->data->signedRenewalInfo|signedTransactionInfo，需要解析
        // @link https://developer.apple.com/documentation/appstoreservernotifications/jwsrenewalinfodecodedpayload
        if (isset($this->payloadData['data']['signedRenewalInfo'])) {
            $this->payloadData['data']['signedRenewalInfo'] = $this->getJwtService()->decodedSignedData($this->payloadData['data']['signedRenewalInfo']);
        }
        // @link https://developer.apple.com/documentation/appstoreservernotifications/jwstransactiondecodedpayload
        if (isset($this->payloadData['data']['signedTransactionInfo'])) {
            $this->payloadData['data']['signedTransactionInfo'] = $this->getJwtService()->decodedSignedData($this->payloadData['data']['signedTransactionInfo']);
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
            JWT::PAYLOAD_IAT => time(),
            JWT::PAYLOAD_EXP => time() + self::JWT_PLAYLOAD_EXP,
            JWT::PAYLOAD_AUD => self::JWT_PLAYLOAD_AUD,
            'bid' => $this->bundleId,
        ];
    }

    /**
     * @return string
     */
    public function getRequestBaseURL(): string
    {
        return $this->environment === self::ENV_PRODUCTION ? self::PRODUCTION_URL : self::SANDBOX_URL;
    }
}