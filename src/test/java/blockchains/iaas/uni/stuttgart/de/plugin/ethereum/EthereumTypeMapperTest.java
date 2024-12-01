/*******************************************************************************
 * Copyright (c) 2019 Institute for the Architecture of Application System - University of Stuttgart
 * Author: Ghareeb Falazi
 *
 * This program and the accompanying materials are made available under the
 * terms the Apache Software License 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

package blockchains.iaas.uni.stuttgart.de.plugin.ethereum;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Bytes8;
import org.web3j.abi.datatypes.generated.Int160;
import org.web3j.abi.datatypes.generated.Uint160;
import org.web3j.abi.datatypes.generated.Uint256;

import java.util.stream.Stream;

class EthereumTypeMapperTest {
    private static Stream<Arguments> provideParams() {
        return Stream.of(
                Arguments.of("{\n" +
                                "\t\"type\": \"string\"\n" +
                                "}",
                        Utf8String.class),
                Arguments.of("{\n" +
                        "\t\"type\": \"string\",\n" +
                        "\t\"pattern\": \"^0x[a-fA-F0-9]{40}$\"\n" +
                        "}", Address.class),
                Arguments.of("{\n" +
                        "\t\"type\": \"integer\",\n" +
                        " \t\"minimum\": 0,\n" +
                        " \t\"maximum\": 1461501637330902918203684832716283019655932542975\n" +
                        "}", Uint160.class),
                Arguments.of("{\n" +
                        "\t\"type\": \"integer\",\n" +
                        " \t\"minimum\": -730750818665451459101842416358141509827966271488,\n" +
                        " \t\"maximum\": 730750818665451459101842416358141509827966271487\n" +
                        "}", Int160.class),
                Arguments.of("{\n" +
                        "\t\"type\": \"array\",\n" +
                        "\t\"maxItems\": 8,\n" +
                        "\t\"items\": {\n" +
                        "\t\t\"type\": \"string\",\n" +
                        "\t\t\"pattern\": \"^[a-fA-F0-9]{2}$\"\n" +
                        "\t}\n" +
                        "}", Bytes8.class),
                Arguments.of("{\n" +
                        "\t\"type\": \"array\",\n" +
                        "\t\"items\": {\n" +
                        "\t\t\"type\": \"string\",\n" +
                        "\t\t\"pattern\": \"^[a-fA-F0-9]{2}$\"\n" +
                        "\t}\n" +
                        "}", DynamicBytes.class),
                Arguments.of("{\n" +
                        "\t\"type\": \"integer\",\n" +
                        " \t\"minimum\": 0,\n" +
                        " \t\"maximum\": 115792089237316195423570985008687907853269984665640564039457584007913129639935\n" +
                        "}", Uint256.class),
                Arguments.of("{\n" +
                        "\t\"type\": \"integer\",\n" +
                        " \t\"minimum\": \"0\",\n" +
                        " \t\"maximum\": \"115792089237316195423570985008687907853269984665640564039457584007913129639935\"\n" +
                        "}", Uint256.class)
                );
    }

    @ParameterizedTest
    @MethodSource("provideParams")
    void testTypes(String type, Class<? extends Type> expectedType) {
        Class<? extends Type> result = EthereumTypeMapper.getEthereumType(type);
        Assertions.assertEquals(expectedType, result);
    }

}