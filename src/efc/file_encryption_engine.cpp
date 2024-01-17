// file_encryption_engine.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <cstring>
#include <efc/file_encryption_engine.hpp>
#include <efc/impl/file_encryption_engine.hpp>

namespace mjx {
    bool file_signature::is_recognized() const noexcept {
        return ::memcmp(data, efc_impl::_Well_known_signature, size) == 0;
    }

    file_metadata construct_metadata() noexcept {
        file_metadata _Meta;
        ::memcpy(_Meta.signature.data, efc_impl::_Well_known_signature, file_signature::size);
        _Meta.salt = generate_salt();
        _Meta.iv   = generate_iv();
        return _Meta;
    }
    
    file_metadata load_metadata(file_stream& _Stream) noexcept {
        static constexpr size_t _Raw_size = sizeof(file_metadata);
        byte_t _Raw[_Raw_size];
        if (_Stream.read(_Raw, _Raw_size) != _Raw_size) { // incomplete section, break
            return file_metadata{};
        }

        file_metadata _Meta;
        efc_impl::_Metadata_parser _Parser(_Raw);
        _Parser._Parse(_Meta.signature.data, file_signature::size);
        _Parser._Parse(_Meta.tag.data(), authentication_tag::size);
        _Parser._Parse(_Meta.salt.data(), salt::size);
        _Parser._Parse(_Meta.iv.data(), iv::size);
        return _Meta;
    }

    bool store_metadata(file_stream& _Stream, const file_metadata& _Meta) noexcept {
        static constexpr size_t _Raw_size = sizeof(file_metadata);
        byte_t _Raw[_Raw_size];
        efc_impl::_Metadata_serializer _Serializer(_Raw);
        _Serializer._Serialize(_Meta.signature.data, file_signature::size);
        _Serializer._Serialize(_Meta.tag.data(), authentication_tag::size);
        _Serializer._Serialize(_Meta.salt.data(), salt::size);
        _Serializer._Serialize(_Meta.iv.data(), iv::size);
        return _Stream.write(_Serializer._Begin(), _Raw_size);
    }

    file_encryption_engine::file_encryption_engine(file_stream& _Src_stream, file_stream& _Dest_stream,
        encryption_engine& _Engine) noexcept : _Mysrc(_Src_stream), _Mydest(_Dest_stream), _Myengine(_Engine) {}

    file_encryption_engine::~file_encryption_engine() noexcept {}

    bool file_encryption_engine::encrypt(const key& _Key, const iv& _Iv, authentication_tag& _Tag) noexcept {
        if (!_Myengine.setup_encryption(_Key, _Iv)) {
            return false;
        }

        static constexpr size_t _Buf_size = 4096;
        byte_t _Rdbuf[_Buf_size];
        byte_t _Wrbuf[_Buf_size];
        size_t _Read;
        for (;;) {
            _Read = _Mysrc.read(_Rdbuf, _Buf_size);
            if (_Read == 0) { // no more data, break
                break;
            }

            if (!_Myengine.encrypt(_Rdbuf, _Read, _Wrbuf)) {
                return false;
            }

            if (!_Mydest.write(_Wrbuf, _Read)) {
                return false;
            }

            if (_Read < _Buf_size) { // no more data, break
                break;
            }
        }

        return _Myengine.complete(_Tag);
    }

    bool file_encryption_engine::decrypt(const key& _Key, const iv& _Iv, authentication_tag& _Tag) noexcept {
        if (!_Myengine.setup_decryption(_Key, _Iv)) {
            return false;
        }

        static constexpr size_t _Buf_size = 4096;
        byte_t _Rdbuf[_Buf_size];
        byte_t _Wrbuf[_Buf_size];
        size_t _Read;
        for (;;) {
            _Read = _Mysrc.read(_Rdbuf, _Buf_size);
            if (_Read == 0) { // no more data, break
                break;
            }

            if (!_Myengine.decrypt(_Rdbuf, _Read, _Wrbuf)) {
                return false;
            }

            if (!_Mydest.write(_Wrbuf, _Read)) {
                return false;
            }

            if (_Read < _Buf_size) { // no more data, break
                break;
            }
        }

        return _Myengine.complete(_Tag);
    }
} // namespace mjx