/**
 * Copyright (c) 2011-2019 libbitcoin developers (see AUTHORS)
 *
 * This file is part of libbitcoin.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <boost/test/unit_test.hpp>

#include <bitcoin/blockchain.hpp>
#include "../utility.hpp"

using namespace bc;
using namespace bc::system;
using namespace bc::blockchain;
using namespace bc::database;

#define TEST_SET_NAME \
   "fast_chain_tests"

class block_chain_accessor
  : public block_chain
{
public:
    block_chain_accessor(threadpool& pool, const blockchain::settings& settings,
        const database::settings& database_settings,
        const system::settings& bitcoin_settings)
      : block_chain(pool, settings, database_settings, bitcoin_settings)
    {
    }

    database::data_base& database()
    {
        return database_;
    }
};

class fast_chain_setup_fixture
{
public:
    fast_chain_setup_fixture()
    {
        test::remove_test_directory(TEST_NAME);
    }

    ~fast_chain_setup_fixture()
    {
        test::remove_test_directory(TEST_NAME);
    }
};

BOOST_FIXTURE_TEST_SUITE(fast_chain_tests, fast_chain_setup_fixture)

BOOST_AUTO_TEST_CASE(block_chain__getters__candidate_and_confirmed__success)
{
    START_BLOCKCHAIN(instance, false);
    const auto bc_settings = bc::system::settings(config::settings::mainnet);
    const chain::block& genesis = bc_settings.genesis_block;

    auto& database = instance.database();

    const auto block1 = NEW_BLOCK(1);
    const auto block2 = NEW_BLOCK(2);

    const auto incoming_headers = std::make_shared<const header_const_ptr_list>(header_const_ptr_list
    {
        std::make_shared<const message::header>(block1->header()),
        std::make_shared<const message::header>(block2->header()),
    });
    const auto outgoing_headers = std::make_shared<header_const_ptr_list>();

    BOOST_REQUIRE_EQUAL(database.reorganize({genesis.hash(), 0}, incoming_headers, outgoing_headers), error::success);

    // Setup ends.

    // Test conditions.
    config::checkpoint top;
    chain::header out_header;
    size_t out_height;
    BOOST_REQUIRE(instance.get_top(top, true));
    BOOST_REQUIRE_EQUAL(top.height(), 2u);
    BOOST_REQUIRE(top.hash() == block2->hash());

    BOOST_REQUIRE(instance.get_top(out_header, out_height, true));
    BOOST_REQUIRE_EQUAL(out_height, 2u);
    BOOST_REQUIRE(out_header.hash() == block2->hash());

    BOOST_REQUIRE(instance.get_top(top, false));
    BOOST_REQUIRE_EQUAL(top.height(), 0u);
    BOOST_REQUIRE(top.hash() == genesis.hash());

    BOOST_REQUIRE(instance.get_top(out_header, out_height, false));
    BOOST_REQUIRE_EQUAL(out_height, 0u);
    BOOST_REQUIRE(out_header.hash() == genesis.hash());

    // Confirm blocks
    database.invalidate(block1->header(), error::success);
    database.update(*block1, 1);
    database.invalidate(block2->header(), error::success);
    database.update(*block2, 2);
    const auto incoming_blocks = std::make_shared<const block_const_ptr_list>(block_const_ptr_list{ block1, block2 });
    const auto outgoing_blocks = std::make_shared<block_const_ptr_list>();
    BOOST_REQUIRE_EQUAL(database.reorganize({genesis.hash(), 0}, incoming_blocks, outgoing_blocks), error::success);

    // Test conditions.
    BOOST_REQUIRE(instance.get_top(top, true));
    BOOST_REQUIRE_EQUAL(top.height(), 2u);
    BOOST_REQUIRE(top.hash() == block2->hash());

    BOOST_REQUIRE(instance.get_top(out_header, out_height, true));
    BOOST_REQUIRE_EQUAL(out_height, 2u);
    BOOST_REQUIRE(out_header.hash() == block2->hash());

    BOOST_REQUIRE(instance.get_top(top, false));
    BOOST_REQUIRE_EQUAL(top.height(), 2u);
    BOOST_REQUIRE(top.hash() == block2->hash());

    BOOST_REQUIRE(instance.get_top(out_header, out_height, false));
    BOOST_REQUIRE_EQUAL(out_height, 2u);
    BOOST_REQUIRE(out_header.hash() == block2->hash());
}

BOOST_AUTO_TEST_CASE(block_chain__get_header2___present_and_not__true_and_false)
{
    START_BLOCKCHAIN(instance, false);
    const auto bc_settings = bc::system::settings(config::settings::mainnet);
    const chain::block& genesis = bc_settings.genesis_block;

    auto& database = instance.database();

    const auto block1 = NEW_BLOCK(1);
    const auto block2 = NEW_BLOCK(2);

    const auto incoming_headers = std::make_shared<const header_const_ptr_list>(header_const_ptr_list
    {
        std::make_shared<const message::header>(block1->header()),
    });
    const auto outgoing_headers = std::make_shared<header_const_ptr_list>();
    BOOST_REQUIRE_EQUAL(database.reorganize({genesis.hash(), 0}, incoming_headers, outgoing_headers), error::success);

    database.invalidate(block1->header(), error::success);
    database.update(*block1, 1);
    const auto incoming_blocks = std::make_shared<const block_const_ptr_list>(block_const_ptr_list{ block1 });
    const auto outgoing_blocks = std::make_shared<block_const_ptr_list>();
    BOOST_REQUIRE_EQUAL(database.reorganize({genesis.hash(), 0}, incoming_blocks, outgoing_blocks), error::success);

    // Setup ends.

    // Test conditions.
    chain::header out_header;
    size_t out_height;
    BOOST_REQUIRE(!instance.get_header(out_header, out_height, block2->hash(), true));
    BOOST_REQUIRE(!instance.get_header(out_header, out_height, block2->hash(), false));

    BOOST_REQUIRE(instance.get_header(out_header, out_height, block1->hash(), true));
    BOOST_REQUIRE_EQUAL(out_height, 1u);
    BOOST_REQUIRE(out_header == block1->header());

    BOOST_REQUIRE(instance.get_header(out_header, out_height, block1->hash(), false));
    BOOST_REQUIRE_EQUAL(out_height, 1u);
    BOOST_REQUIRE(out_header == block1->header());
}

BOOST_AUTO_TEST_CASE(block_chain__get_block_error___present_and_not__true_and_false)
{
    START_BLOCKCHAIN(instance, false);
    const auto bc_settings = bc::system::settings(config::settings::mainnet);
    const chain::block& genesis = bc_settings.genesis_block;

    auto& database = instance.database();

    const auto block1 = NEW_BLOCK(1);
    const auto block2 = NEW_BLOCK(2);

    const auto incoming_headers = std::make_shared<const header_const_ptr_list>(header_const_ptr_list
    {
        std::make_shared<const message::header>(block1->header()),
    });
    const auto outgoing_headers = std::make_shared<header_const_ptr_list>();
    BOOST_REQUIRE_EQUAL(database.reorganize({genesis.hash(), 0}, incoming_headers, outgoing_headers), error::success);

    database.invalidate(block1->header(), error::success);
    database.update(*block1, 1);
    const auto incoming_blocks = std::make_shared<const block_const_ptr_list>(block_const_ptr_list{ block1 });
    const auto outgoing_blocks = std::make_shared<block_const_ptr_list>();
    BOOST_REQUIRE_EQUAL(database.reorganize({genesis.hash(), 0}, incoming_blocks, outgoing_blocks), error::success);

    // Setup ends.

    // Test conditions.
    code out_error;
    BOOST_REQUIRE(!instance.get_block_error(out_error, block2->hash()));

    BOOST_REQUIRE(instance.get_block_error(out_error, block1->hash()));
    BOOST_REQUIRE_EQUAL(out_error, error::success);
}

BOOST_AUTO_TEST_CASE(block_chain__get_bits___present_and_not__true_and_false)
{
    START_BLOCKCHAIN(instance, false);
    const auto bc_settings = bc::system::settings(config::settings::mainnet);
    const chain::block& genesis = bc_settings.genesis_block;

    auto& database = instance.database();

    const auto block1 = NEW_BLOCK(1);
    const auto block2 = NEW_BLOCK(2);
    std::cerr << block1->header().bits() << std::endl;
    std::cerr << block2->header().bits() << std::endl;

    const auto incoming_headers = std::make_shared<const header_const_ptr_list>(header_const_ptr_list
    {
        std::make_shared<const message::header>(block1->header()),
        std::make_shared<const message::header>(block2->header()),
    });
    const auto outgoing_headers = std::make_shared<header_const_ptr_list>();
    BOOST_REQUIRE_EQUAL(database.reorganize({genesis.hash(), 0}, incoming_headers, outgoing_headers), error::success);

    database.invalidate(block1->header(), error::success);
    database.update(*block1, 1);
    const auto incoming_blocks = std::make_shared<const block_const_ptr_list>(block_const_ptr_list{ block1 });
    const auto outgoing_blocks = std::make_shared<block_const_ptr_list>();
    BOOST_REQUIRE_EQUAL(database.reorganize({genesis.hash(), 0}, incoming_blocks, outgoing_blocks), error::success);

    // Setup ends.

    // Test conditions.
    uint32_t out_bits;
    BOOST_REQUIRE(instance.get_bits(out_bits, 2, true));
    BOOST_REQUIRE_EQUAL(out_bits, block2->header().bits());

    BOOST_REQUIRE(instance.get_bits(out_bits, 1, false));
    BOOST_REQUIRE_EQUAL(out_bits, block1->header().bits());

    BOOST_REQUIRE(!instance.get_bits(out_bits, 2, false));
}

////BOOST_AUTO_TEST_CASE(block_chain__push__flushed__expected)
////{
////    START_BLOCKCHAIN(instance, true);
////
////    const auto block1 = NEW_BLOCK(1);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////    const auto state1 = instance.get_block_state(block1->hash());
////    BOOST_REQUIRE(is_confirmed(state1));
////    const auto state0 = instance.get_block_state(chain::block::genesis_mainnet().hash());
////    BOOST_REQUIRE(is_confirmed(state0));
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__push__unflushed__expected_block)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////    const auto state1 = instance.get_block_state(block1->hash());
////    BOOST_REQUIRE(is_confirmed(state1));
////    const auto state0 = instance.get_block_state(chain::block::genesis_mainnet().hash());
////    BOOST_REQUIRE(is_confirmed(state0));
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_block_hash__not_found__false)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    hash_digest hash;
////    BOOST_REQUIRE(!instance.get_block_hash(hash, 1, false));
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_block_hash__found__true)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////
////    hash_digest hash;
////    BOOST_REQUIRE(instance.get_block_hash(hash, 1, false));
////    BOOST_REQUIRE(hash == block1->hash());
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_branch_work__height_above_top__true)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    uint256_t work;
////    uint256_t overcome(max_uint64);
////
////    // This is allowed and just returns zero (standard new single block).
////    BOOST_REQUIRE(instance.get_work(work, overcome, 1, false));
////    BOOST_REQUIRE_EQUAL(work, 0);
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_branch_work__overcome_zero__true)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    uint256_t work;
////    uint256_t overcome(0);
////
////    // This should not exit early.
////    BOOST_REQUIRE(instance.get_work(work, overcome, 0, false));
////    BOOST_REQUIRE_EQUAL(work, genesis_mainnet_work);
////}
////
////
////BOOST_AUTO_TEST_CASE(block_chain__get_branch_work__maximum_one__true)
////{
////    static const uint64_t genesis_mainnet_work = 0x0000000100010001;
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////    uint256_t work;
////    uint256_t overcome(block1->header().proof());
////
////    // This should not exit early due to tying on the first block (order matters).
////    BOOST_REQUIRE(instance.get_work(work, overcome, 0, false));
////    BOOST_REQUIRE_EQUAL(work, genesis_mainnet_work + block1->header().proof());
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_branch_work__unbounded__true)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    const auto block2 = NEW_BLOCK(2);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////    BOOST_REQUIRE(instance.push(block2, 2, 0));
////
////    uint256_t work;
////    uint256_t overcome(max_uint64);
////
////    // This should not exit early but skips the genesis block.
////    BOOST_REQUIRE(instance.get_work(work, overcome, 1, false));
////    BOOST_REQUIRE_EQUAL(work, block1->header().proof() + block2->header().proof());
////}
////
////////BOOST_AUTO_TEST_CASE(block_chain__get_height__not_found__false)
////////{
////////    START_BLOCKCHAIN(instance, false);
////////
////////    size_t height;
////////    BOOST_REQUIRE(!instance.get_block_height(height, null_hash, true));
////////}
////////
////////BOOST_AUTO_TEST_CASE(block_chain__get_height__found__true)
////////{
////////    START_BLOCKCHAIN(instance, false);
////////
////////    const auto block1 = NEW_BLOCK(1);
////////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////////
////////    size_t height;
////////    BOOST_REQUIRE(instance.get_block_height(height, block1->hash(), true));
////////    BOOST_REQUIRE_EQUAL(height, 1u);
////////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_bits__not_found__false)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    uint32_t bits;
////    BOOST_REQUIRE(!instance.get_bits(bits, 1, false));
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_bits__found__true)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////
////    uint32_t bits;
////    BOOST_REQUIRE(instance.get_bits(bits, 1, false));
////    BOOST_REQUIRE_EQUAL(bits, block1->header().bits());
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_timestamp__not_found__false)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    uint32_t timestamp;
////    BOOST_REQUIRE(!instance.get_timestamp(timestamp, 1, false));
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_timestamp__found__true)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////
////    uint32_t timestamp;
////    BOOST_REQUIRE(instance.get_timestamp(timestamp, 1, false));
////    BOOST_REQUIRE_EQUAL(timestamp, block1->header().timestamp());
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_version__not_found__false)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    uint32_t version;
////    BOOST_REQUIRE(!instance.get_version(version, 1, false));
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__get_version__found__true)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////
////    uint32_t version;
////    BOOST_REQUIRE(instance.get_version(version, 1, false));
////    BOOST_REQUIRE_EQUAL(version, block1->header().version());
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__populate_output__not_found__false)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const chain::output_point outpoint{ null_hash, 42 };
////    size_t header_branch_height = 0;
////    instance.populate_output(outpoint, header_branch_height);
////    BOOST_REQUIRE(!outpoint.metadata.cache.is_valid());
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__populate_output__found__expected)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    const auto block2 = NEW_BLOCK(2);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////    BOOST_REQUIRE(instance.push(block2, 2, 0));
////
////    const chain::output_point outpoint{ block2->transactions()[0].hash(), 0 };
////    const auto expected_value = initial_block_subsidy_satoshi();
////    const auto expected_script = block2->transactions()[0].outputs()[0].script().to_string(0);
////    instance.populate_output(outpoint, 2);
////    BOOST_REQUIRE(outpoint.metadata.cache.is_valid());
////
////    BOOST_REQUIRE(outpoint.metadata.coinbase);
////    BOOST_REQUIRE_EQUAL(outpoint.metadata.height, 2u);
////    BOOST_REQUIRE_EQUAL(outpoint.metadata.cache.value(), expected_value);
////    BOOST_REQUIRE_EQUAL(outpoint.metadata.cache.script().to_string(0), expected_script);
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__populate_output__below_fork__true)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    const auto block2 = NEW_BLOCK(2);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////    BOOST_REQUIRE(instance.push(block2, 2, 0));
////
////    const chain::output_point outpoint{ block2->transactions().front().hash(), 0 };
////    instance.populate_output(outpoint, 3);
////    BOOST_REQUIRE(outpoint.metadata.cache.is_valid());
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__populate_output__at_fork__true)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    const auto block2 = NEW_BLOCK(2);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////    BOOST_REQUIRE(instance.push(block2, 2, 0));
////
////    const chain::output_point outpoint{ block2->transactions().front().hash(), 0 };
////    instance.populate_output(outpoint, 2);
////    BOOST_REQUIRE(outpoint.metadata.cache.is_valid());
////}
////
////BOOST_AUTO_TEST_CASE(block_chain__populate_output__above_fork__false)
////{
////    START_BLOCKCHAIN(instance, false);
////
////    const auto block1 = NEW_BLOCK(1);
////    const auto block2 = NEW_BLOCK(2);
////    BOOST_REQUIRE(instance.push(block1, 1, 0));
////    BOOST_REQUIRE(instance.push(block2, 2, 0));
////
////    const chain::output_point outpoint{ block2->transactions().front().hash(), 0 };
////    instance.populate_output(outpoint, 1);
////    BOOST_REQUIRE(!outpoint.metadata.cache.is_valid());
////}
////
BOOST_AUTO_TEST_SUITE_END()
