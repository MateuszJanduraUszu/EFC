// encryption_engine.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_TEST_UNIT_ENCRYPTION_ENGINE_HPP_
#define _EFC_TEST_UNIT_ENCRYPTION_ENGINE_HPP_
#include <efc/encryption_engine.hpp>
#include <efc/impl/random.hpp>
#include <gtest/gtest.h>
#include <mjstr/string.hpp>
#include <mjstr/string_view.hpp>

namespace mjx {
    namespace test {
        inline key _Generate_key() noexcept {
            key _Key;
            return efc_impl::_Random_bytes(_Key.data(), key::size) ? _Key : key{};
        }

        inline bool _Run_encryption_engine_test(const utf8_string_view _Text) {
            const key& _Key = _Generate_key();
            const iv& _Iv   = generate_iv();
            authentication_tag _Tag;
            encryption_engine _Engine;
            byte_string _Enc_buf(_Text.size(), '\0');
            if (!_Engine.setup_encryption(_Key, _Iv) || !_Engine.encrypt(reinterpret_cast<const byte_t*>(
                _Text.data()), _Text.size(), _Enc_buf.data()) || !_Engine.complete(_Tag)) {
                return false;
            }

            utf8_string _Dec_buf(_Text.size(), '\0');
            if (!_Engine.setup_decryption(_Key, _Iv) || !_Engine.decrypt(_Enc_buf.c_str(), _Enc_buf.size(),
                reinterpret_cast<byte_t*>(_Dec_buf.data())) || !_Engine.complete(_Tag)) {
                return false;
            }

            EXPECT_EQ(_Dec_buf, _Text);
            return true;
        }

        TEST(encryption_engine, empty_text) {
            _Run_encryption_engine_test("");
            _Run_encryption_engine_test("");
            _Run_encryption_engine_test("");
            _Run_encryption_engine_test("");
            _Run_encryption_engine_test("");
            _Run_encryption_engine_test("");
            _Run_encryption_engine_test("");
            _Run_encryption_engine_test("");
            _Run_encryption_engine_test("");
            _Run_encryption_engine_test("");
        }

        TEST(encryption_engine, short_text) {
            _Run_encryption_engine_test("The quick brown fox jumps over the lazy dog.");
            _Run_encryption_engine_test("Pack my box with five dozen liquor jugs.");
            _Run_encryption_engine_test("Jackdaws love my big sphinx of quartz.");
            _Run_encryption_engine_test("How vexingly quick daft zebras jump!");
            _Run_encryption_engine_test("Bright vixens jump; dozy fowl quack.");
            _Run_encryption_engine_test("Sphinx of black quartz, judge my vow.");
            _Run_encryption_engine_test("Quick zephyrs blow, vexing daft Jim.");
            _Run_encryption_engine_test("Two driven jocks help fax my big quiz.");
            _Run_encryption_engine_test("Five quacking zephyrs jolt my wax bed.");
            _Run_encryption_engine_test("Jinxed wizards pluck ivy from the big quilt.");
        }

        TEST(encryption_engine, long_text) {
            _Run_encryption_engine_test(
                "It was a calm summer evening, and the sun was setting slowly. Alice Johnson, her hair tied "
                "up in a loose bun, walked briskly through the park, her dog trailing behind her. "
                "The park was filled with the sound of children's laughter and the distant hum of traffic. "
                "A gentle breeze rustled the leaves, bringing with it the sweet scent of blooming flowers."
            );
            _Run_encryption_engine_test(
                "It was a stormy night in December, and the snow was falling heavily. John Smith, his coat "
                "pulled tight around him, trudged through the snow, his boots crunching with every step. "
                "The street was deserted, the only sound the howling wind and the occasional distant car horn. "
                "His breath fogged up in the cold air, disappearing almost as quickly as it appeared."
            );
            _Run_encryption_engine_test(
                "It was a sunny spring morning, and the birds were chirping happily. Sarah Williams, her "
                "basket filled with fresh produce, strolled through the farmer's market, taking in the "
                "vibrant colors and enticing smells. The market was bustling with activity, vendors calling "
                "out their wares and customers haggling over prices. A sense of community and camaraderie "
                "filled the air, making it a truly enjoyable experience."
            );
            _Run_encryption_engine_test(
                "It was a humid afternoon in July, and the heat was almost unbearable. Mike Brown, his "
                "shirt sticking to his back, hurried through the crowded city streets, seeking refuge "
                "in the shade. The city was alive with the sound of honking cars, chattering pedestrians, "
                "and the occasional street performer. Despite the heat, there was an energy in the air "
                "that was uniquely New York."
            );
            _Run_encryption_engine_test(
                "It was a chilly autumn day in October, and the leaves were turning shades of red and gold. "
                "Emily Davis, her scarf wrapped tightly around her neck, wandered through the woods, her camera "
                "in hand. The woods were quiet, the only sound the rustling of leaves and the occasional bird song. "
                "The beauty of nature was on full display, providing endless inspiration for her photography."
            );
            _Run_encryption_engine_test(
                "It was a clear night in August, and the stars were shining brightly. David Miller, "
                "his telescope set up, gazed up at the night sky, marveling at the vastness of the universe. "
                "The night was silent, the only sound the distant hoot of an owl and the rustling of leaves. "
                "The beauty and mystery of the cosmos filled him with a sense of awe and wonder."
            );
            _Run_encryption_engine_test(
                "It was a rainy day in April, and the sound of raindrops hitting the roof was soothing. "
                "Laura Wilson, her book in hand, sat by the window, watching the rain. The room was cozy, "
                "the only light coming from the soft glow of the fireplace. The smell of freshly brewed "
                "coffee filled the air, adding to the comforting atmosphere."
            );
            _Run_encryption_engine_test(
                "It was a windy day in March, and the trees were swaying wildly. Robert Taylor, his hat "
                "held firmly in place, walked along the beach, the sand whipping around him. The beach "
                "was deserted, the only sound the crashing waves and the whistling wind. Despite the "
                "harsh conditions, there was a certain beauty in the raw power of nature."
            );
            _Run_encryption_engine_test(
                "It was a foggy morning in November, and visibility was low. Lisa Anderson, her flashlight "
                "in hand, navigated through the fog, her dog leading the way. The fog gave the world an "
                "eerie, otherworldly feel, the familiar made unfamiliar. Despite the poor visibility, "
                "there was a sense of peace and tranquility in the solitude."
            );
            _Run_encryption_engine_test(
                "It was a hot day in June, and the sun was shining brightly. James Thompson, his sunglasses "
                "on, lounged by the pool, a cold drink in his hand. The sound of splashing water and "
                "distant laughter filled the air. The day was perfect, a welcome break from the hustle "
                "and bustle of everyday life."
            );
        }
    } // namespace test
} // namespace mjx

#endif // _EFC_TEST_UNIT_ENCRYPTION_ENGINE_HPP_