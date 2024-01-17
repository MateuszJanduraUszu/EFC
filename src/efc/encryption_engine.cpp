// encryption_engine.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <efc/encryption_engine.hpp>
#include <efc/impl/random.hpp>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

namespace mjx {
    iv generate_iv() noexcept {
        iv _Iv;
        return efc_impl::_Random_bytes(_Iv.data(), iv::size) ? _Iv : iv{};
    }

    encryption_engine::encryption_engine() noexcept
        : _Mystate(_Uninitialized), _Myctx(::EVP_CIPHER_CTX_new()) {}

    encryption_engine::~encryption_engine() noexcept {
        if (_Myctx) {
            ::EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(_Myctx));
            _Myctx = nullptr;
        }
    }

    bool encryption_engine::_Get_tag(authentication_tag& _Tag) noexcept {
        OSSL_PARAM _Params[2] = {0}; // tag + terminating element
        _Params[0].key        = "tag";
        _Params[0].data       = _Tag.data();
        _Params[0].data_type  = OSSL_PARAM_OCTET_STRING;
        _Params[0].data_size  = authentication_tag::size;
        return ::EVP_CIPHER_CTX_get_params(static_cast<EVP_CIPHER_CTX*>(_Myctx), _Params) != 0;
    }

    bool encryption_engine::_Set_tag(authentication_tag& _Tag) noexcept {
        OSSL_PARAM _Params[2] = {0}; // tag + terminating element
        _Params[0].key        = "tag";
        _Params[0].data       = _Tag.data();
        _Params[0].data_type  = OSSL_PARAM_OCTET_STRING;
        _Params[0].data_size  = authentication_tag::size;
        return ::EVP_CIPHER_CTX_set_params(static_cast<EVP_CIPHER_CTX*>(_Myctx), _Params) != 0;
    }

    bool encryption_engine::_Complete(authentication_tag& _Tag) noexcept {
        EVP_CIPHER_CTX* const _Ctx = static_cast<EVP_CIPHER_CTX*>(_Myctx);
        int _Unused                = 0; // number of encrypted/decrypted bytes (unused)
        if (_Mystate == _Initialized_for_encryption) { // complete encryption
            return ::EVP_EncryptFinal_ex(_Ctx, nullptr, &_Unused) != 0 && _Get_tag(_Tag);
        } else { // complete decryption
            return _Set_tag(_Tag) && ::EVP_DecryptFinal_ex(_Ctx, nullptr, &_Unused) != 0;
        }
    }

    bool encryption_engine::setup_encryption(const key& _Key, const iv& _Iv) noexcept {
        if (_Mystate != _Uninitialized) { // engine already initialized, break
            return false;
        }

        if (::EVP_EncryptInit_ex(
            static_cast<EVP_CIPHER_CTX*>(_Myctx), ::EVP_aes_256_gcm(), nullptr, _Key.data(), _Iv.data()) == 0) {
            return false;
        }

        _Mystate = _Initialized_for_encryption;
        return true;
    }

    bool encryption_engine::setup_decryption(const key& _Key, const iv& _Iv) noexcept {
        if (_Mystate != _Uninitialized) { // engine already initialized, break
            return false;
        }

        if (::EVP_DecryptInit_ex(
            static_cast<EVP_CIPHER_CTX*>(_Myctx), ::EVP_aes_256_gcm(), nullptr, _Key.data(), _Iv.data()) == 0) {
            return false;
        }

        _Mystate = _Initialized_for_decryption;
        return true;
    }

    bool encryption_engine::encrypt(const byte_t* const _Bytes, const size_t _Count, byte_t* const _Buf) noexcept {
        if (_Mystate != _Initialized_for_encryption) { // engine not initialized for encryption, break
            return false;
        }

        int _Unused = 0; // number of encrypted bytes (unused)
        return ::EVP_EncryptUpdate(
            static_cast<EVP_CIPHER_CTX*>(_Myctx), _Buf, &_Unused, _Bytes, static_cast<int>(_Count)) != 0;
    }

    bool encryption_engine::decrypt(const byte_t* const _Bytes, const size_t _Count, byte_t* const _Buf) noexcept {
        if (_Mystate != _Initialized_for_decryption) { // engine not initialized for decryption, break
            return false;
        }

        int _Unused = 0; // number of decrypted bytes (unused)
        return ::EVP_DecryptUpdate(
            static_cast<EVP_CIPHER_CTX*>(_Myctx), _Buf, &_Unused, _Bytes, static_cast<int>(_Count)) != 0;
    }

    bool encryption_engine::complete(authentication_tag& _Tag) noexcept {
        if (_Mystate == _Uninitialized) { // engine uninitialized, break
            return false;
        }

        if (!_Complete(_Tag)) { // failed to complete encryption/decryption
            return false;
        }

        ::EVP_CIPHER_CTX_reset(static_cast<EVP_CIPHER_CTX*>(_Myctx)); // reset engine context
        _Mystate = _Uninitialized; // reset engine state
        return true;
    }
} // namespace mjx