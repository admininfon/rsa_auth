<?php
/**
 * Created by PhpStorm.
 * User: kangkst
 * Date: 2018/04/25
 * Time: 15:15
 */
namespace TlsAuth;


class TlsAuth
{
    // 函数返回结果集
    private $res = ['status' => false, 'msg' => 'Undefined', 'data' => null];

    // 私钥
    private $private_key = null;
    // 公钥
    private $public_key = null;
    // 加密方法
    private $md_method = 'sha256';

    /**
     * TlsAuth constructor.
     *
     * @param array $config [optional] 配置参数
     */
    public function __construct($config = array())
    {
        if (!extension_loaded('openssl')) {
            trigger_error('need openssl extension', E_USER_ERROR);
        }

        if (!empty($config['md_method'])) {
            $this->md_method = $config['md_method'];
        }

        if (!in_array($this->md_method, openssl_get_md_methods(), true)) {
            trigger_error('need openssl support ' . $this->md_method, E_USER_ERROR);
        }

        if (!empty($config['private_key'])) {
            $result = $this->setPrivateKey($config['private_key']);
            if (!$result['status']) {
                trigger_error($result['msg'], E_USER_ERROR);
            }
        }

        if (!empty($config['public_key'])) {
            $result = $this->setPublicKey($config['public_key']);
            if (!$result['status']) {
                trigger_error($result['msg'], E_USER_ERROR);
            }
        }
    }

    /**
     * 设置私钥
     *
     * @author kangkst <kst157521@163.com>
     * @since 1.0.0
     * @date 2018-03-20 15:18:46
     * @param string $private_key
     * @return array
     */
    public function setPrivateKey($private_key)
    {
        if (!file_get_contents($private_key)) {
            $this->res['msg'] = 'The parameter "private_key" is not defined.';
            return $this->res;
        }
        $this->private_key = openssl_pkey_get_private(file_get_contents($private_key));
        if ($this->private_key === false) {
            $this->res['status'] = false;
            $this->res['msg'] = openssl_error_string();
            return $this->res;
        }
        $this->res['status'] = true;
        $this->res['msg'] = 'successful';
        return $this->res;
    }

    /**
     * 设置公钥
     *
     * @param mixed|null $public_key
     * @return array
     */
    public function setPublicKey($public_key)
    {
        if (empty($public_key)) {
            $this->res['msg'] = 'The parameter "public_key" is not defined.';
            return $this->res;
        }
        $this->public_key = openssl_pkey_get_public(file_get_contents($public_key));
        if ($this->public_key === false) {
            $this->res['status'] = false;
            $this->res['msg'] = openssl_error_string();
            return $this->res;
        }
        $this->res['status'] = true;
        $this->res['msg'] = 'successful';
        return $this->res;
    }

    /**
     * base64编码
     *
     * @author kangkst <kst157521@163.com>
     * @since 1.0.0
     * @date 2018-03-20 15:47:45
     * @param string $string
     * @return array
     */
    private function base64Encode($string)
    {
        static $replace = Array('+' => '*', '/' => '-', '=' => '_');
        $base64 = base64_encode($string);
        if ($base64 === false) {
            $this->res['status'] = false;
            $this->res['msg'] = 'base64_encode error!';
            $this->res['data'] = null;
            return $this->res;
        }

        $this->res['status'] = true;
        $this->res['msg'] = 'successful';
        $this->res['data'] = str_replace(array_keys($replace), array_values($replace), $base64);
        return $this->res;
    }

    /**
     * base64解码
     *
     * @author kangkst <kst157521@163.com>
     * @since 1.0.0
     * @date 2018-03-20 15:52:07
     * @param string $base64
     * @return array
     */
    private function base64Decode($base64)
    {
        static $replace = Array('+' => '*', '/' => '-', '=' => '_');
        $string = str_replace(array_values($replace), array_keys($replace), $base64);
        $result = base64_decode($string);
        if ($result == false) {
            $this->res['status'] = false;
            $this->res['msg'] = 'base64_decode error';
            $this->res['data'] = null;
            return $this->res;
        }

        $this->res['status'] = true;
        $this->res['msg'] = 'successful';
        $this->res['data'] = $result;
        return $this->res;
    }

    /**
     * 生成签名内容
     *
     * @author kangkst <kst157521@163.com>
     * @since 1.0.0
     * @date 2018-03-20 16:08:27
     * @param array $data
     * @return array
     */
    private function genSignContent($data = array())
    {
        static $members = ['data', 'expire_after', 'time'];
        $content = [];
        foreach ($members as $member) {
            if (!isset($data[$member])) {
                $this->res['status'] = false;
                $this->res['msg'] = 'json need ' . $member;
                $this->res['data'] = null;
                return $this->res;
            }
            $content[$member] = $data[$member];
        }

        if (empty($content)) {
            $this->res['status'] = false;
            $this->res['msg'] = 'Not Defined';
            $this->res['data'] = null;
        } else {
            $this->res['status'] = true;
            $this->res['msg'] = 'successful';
            $this->res['data'] = json_encode($content);
        }
        return $this->res;
    }

    /**
     * 数据加密
     *
     * @author kangkst <kst157521@163.com>
     * @since 1.0.0
     * @date 2018-03-20 16:32:54
     * @param string $data
     * @param int $expire
     * @return array
     */
    public function genSig($data, $expire = 0)
    {
        $json = [
            'data' => (string)$data,
            'expire_after' => $expire,
            'time' => time()
        ];

        $gen_sig_content = '';
        $result_gen_sig_content = $this->genSignContent($json);
        if ($result_gen_sig_content['status']) {
            $gen_sig_content = $result_gen_sig_content['data'];
        } else {
            return $result_gen_sig_content;
        }

        $signature = '';
        $result_sign = $this->sign($gen_sig_content);
        if ($result_sign['status']) {
            $signature = $result_sign['data'];
        } else {
            return $result_sign;
        }

        $json['sign'] = base64_encode($signature);
        if ($json['sign'] === false) {
            $this->res['status'] = false;
            $this->res['msg'] = 'base64_encode error';
            $this->res['data'] = null;
            return $this->res;
        }

        $json_text = json_encode($json);
        if ($json_text === false) {
            $this->res['status'] = false;
            $this->res['msg'] = 'json_encode error';
            $this->res['data'] = null;
            return $this->res;
        }

        $compressed = gzcompress($json_text);
        if ($compressed === false) {
            $this->res['status'] = false;
            $this->res['msg'] = 'gzcompress error';
            $this->res['data'] = null;
            return $this->res;
        }

        $result_sign_info = $this->base64Encode($compressed);
        return $result_sign_info;
    }

    /**
     * 生成加密数据
     *
     * @author kangkst <kst157521@163.com>
     * @since 1.0.0
     * @date 2018-03-20 16:18:57
     * @param $data
     * @return array
     */
    private function sign($data)
    {
        if (empty($data)) {
            $this->res['status'] = false;
            $this->res['msg'] = 'The parameter "data" is not defined.';
            $this->res['data'] = null;
            return $this->res;
        }

        $signature = '';
        if (!openssl_sign($data, $signature, $this->private_key, $this->md_method)) {
            $this->res['status'] = false;
            $this->res['msg'] = openssl_error_string();
            $this->res['data'] = null;
            return $this->res;
        }

        if (empty($signature)) {
            $this->res['status'] = false;
            $this->res['msg'] = 'Not Defined';
            $this->res['data'] = null;
        } else {
            $this->res['status'] = true;
            $this->res['msg'] = 'successful';
            $this->res['data'] = $signature;
        }
        return $this->res;
    }

    /**
     * 解密数据
     *
     * 说明：返回数据中，索引为“sign_expire_time”代表数据有效时间，只有大于“0”的才视为设置过期时间，如若数据过期，将不会
     * 返回数据。
     *
     * @author kangkst <kst157521@163.com>
     * @since 1.0.0
     * @date 2018-03-20 17:00:47
     * @param string $sig
     * @return array
     */
    public function verifySig($sig)
    {
        $decoded_sig_result = $this->base64Decode($sig);
        $uncompressed_sig = false;
        if ($decoded_sig_result['status']) {
            $uncompressed_sig = gzuncompress($decoded_sig_result['data']);
        }

        if ($uncompressed_sig === false) {
            $this->res['status'] = false;
            $this->res['data'] = null;
            $this->res['msg'] = 'gzuncompress error';
            return $this->res;
        }

        $json = json_decode($uncompressed_sig, true);
        if ($json == false) {
            $this->res['status'] = false;
            $this->res['data'] = null;
            $this->res['msg'] = 'json_decode error';
            return $this->res;
        }

        $content_result = $this->genSignContent($json);
        if (!$content_result['status']) {
            return $content_result;
        }

        $signature = base64_decode($json['sign']);
        if ($signature == false) {
            $this->res['status'] = false;
            $this->res['data'] = null;
            $this->res['msg'] = 'sign json_decode error';
            return $this->res;
        }

        $result = $this->verify($content_result['data'], $signature);
        if (!$result['status']) {
            return $result;
        }

        $sign_data = $json['data'];
        $init_time = $json['time'];
        $expire_time = $json['expire_after'];
        $data_off_time = $init_time + $expire_time;

        // 检测数据是否过期，过期时间为空或未设置，则判定永久有效
        if (!empty($expire_time) && $data_off_time < time()) {
            $this->res['status'] = false;
            $this->res['data'] = null;
            $this->res['msg'] = 'Data expired!';
            return $this->res;
        }

        $res_data = ['sign_data' => $sign_data, 'sign_init_time' => $init_time, 'sign_expire_time' => $expire_time];
        if (empty(array_filter($res_data))) {
            $this->res['status'] = false;
            $this->res['msg'] = 'Not Defined';
            $this->res['data'] = [];
        } else {
            $this->res['status'] = true;
            $this->res['msg'] = 'successful';
            $this->res['data'] = $res_data;
        }
        return $this->res;
    }

    /**
     * 生成解码数据
     *
     * @author kangkst <kst157521@163.com>
     * @since 1.0.0
     * @date 2018-03-20 16:52:05
     * @param string $data
     * @param string $sig
     * @return array
     */
    private function verify($data, $sig)
    {
        $ret = openssl_verify($data, $sig, $this->public_key, $this->md_method);
        if ($ret == -1) {
            $this->res['status'] = false;
            $this->res['msg'] = openssl_error_string();
            $this->res['data'] = null;
        } else {
            $this->res['status'] = true;
            $this->res['msg'] = 'successful';
            $this->res['data'] = $ret;
        }
        return $this->res;
    }
}
