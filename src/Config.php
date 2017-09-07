<?php

namespace PTLS;

use PTLS\Exceptions\TLSException;
use PTLS\EcDSA;

class Config
{
    const SERVER = true;
    const CLIENT = false;

    private $config;
    private $isServer;

    public function __construct(bool $isServer, array $arrConfig)
    {
        $this->isServer = $isServer;
        $this->config   = [];

        if ($isServer) {
            $this->encodeServerConfig($arrConfig);
        } else {
            $this->encodeClientConfig($arrConfig);
        }
    }

    private function encodeClientConfig(array $arrConfig)
    {
        // Setting up TLS version
        if (isset($arrConfig['version'])) {
            $this->config['version'] = $arrConfig['version'];
        }
    }

    private function encodeServerConfig(array $arrConfig)
    {
        if (!isset($arrConfig['key_pair_files'])) {
            throw new TLSException("No keyPairFiles");
        }

        $keyPairFiles = $arrConfig['key_pair_files'];

        if (!isset($keyPairFiles['cert']) || !file_exists($keyPairFiles['cert'][0])) {
            throw new TLSException("Invalid cert path of keyPair");
        }

        if (!isset($keyPairFiles['key']) || !file_exists($keyPairFiles['key'][0])) {
            throw new TLSException("Invalid key path of keyPair");
        }

        $pemCrtFiles     = $keyPairFiles['cert'];
        $pemPriFile      = $keyPairFiles['key'][0];
        $pemPriPassCode  = $keyPairFiles['key'][1];

        $pemPrivate      = file_get_contents($pemPriFile);

        $this->config['crt_ders'] = X509::crtFilePemToDer($pemCrtFiles);

        $this->config['private_key_pem'] = $pemPrivate;

        // Check for ECDSA
        if (EcDSA::isValidPrivateKey($pemPrivate)) {
            $this->config['is_ecdsa'] = true;
            // Get a ECDSA instance for Signature Algorithm
            $this->config['ecdsa'] = new EcDSA($pemPrivate);
        } else { // RSA
            $this->config['is_ecdsa'] = false;
            $this->config['private_key'] = X509::getPrivateKey($pemPrivate, $pemPriPassCode);
        }
    }

    public function get($key, $default = null)
    {
        return (isset($this->config[$key])) ? $this->config[$key] : $default;
    }

    public function isServer()
    {
        return $this->isServer;
    }
}
