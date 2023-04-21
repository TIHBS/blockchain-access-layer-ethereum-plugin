/*******************************************************************************
 * Copyright (c) 2019-2022 Institute for the Architecture of Application System - University of Stuttgart
 * Author: Ghareeb Falazi
 * Co-author: Akshay Patel
 *
 * This program and the accompanying materials are made available under the
 * terms the Apache Software License 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/
package blockchains.iaas.uni.stuttgart.de.plugin.ethereum;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutionException;

import blockchains.iaas.uni.stuttgart.de.api.model.LinearChainTransaction;
import blockchains.iaas.uni.stuttgart.de.api.model.Parameter;
import blockchains.iaas.uni.stuttgart.de.api.model.Transaction;

import blockchains.iaas.uni.stuttgart.de.api.utils.PoWConfidenceCalculator;
import blockchains.iaas.uni.stuttgart.de.plugin.ethereum.contracts.Permissions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.WalletUtils;
import org.web3j.tx.gas.DefaultGasProvider;

/**
 * To run these tests, you need ganache with the following mnemonic:
 * smart contract composition
 */
class EthereumAdapterTest {
    private static final String MESSAGE = "This was not a difficult task!";
    private final String BYTES_TYPE = "{\n" +
            "\t\"type\": \"array\",\n" +
            "\t\"items\": {\n" +
            "\t\t\"type\": \"string\",\n" +
            "\t\t\"pattern\": \"^[a-fA-F0-9]{2}$\"\n" +
            "\t}\n" +
            "}";
    private final String ADDRESS_TYPE = "{\n" +
            "\t\"type\": \"string\",\n" +
            "\t\"pattern\": \"^0x[a-fA-F0-9]{40}$\"\n" +
            "}";
    private static final double REQUIRED_CONFIDENCE = 0.6;
    private EthereumAdapter adapter;
    private static final Logger log = LoggerFactory.getLogger(EthereumAdapterTest.class);

    @BeforeEach
    void init() {
        this.adapter = getAdapter();
    }

    @Test
    void testConnectionToNode() {
        Assertions.assertEquals("true", this.adapter.testConnectionToNode());
    }

    @Test
    void testSendTransaction() throws ExecutionException, InterruptedException {
        final String toAddress = "0x182761AC584C0016Cdb3f5c59e0242EF9834fef0";
        final BigDecimal value = new BigDecimal(5000);
        LinearChainTransaction result = (LinearChainTransaction) this.adapter.submitTransaction(toAddress, value, REQUIRED_CONFIDENCE).get();
        log.debug("transaction hash is: " + result.getTransactionHash());
    }

    @Test
    void testInvokeSmartContract() throws Exception {
        Permissions contract = this.deployContract();
        String smartContractPath = contract.getContractAddress();
        String functionIdentifier = "setPublicKey";
        byte[] bytes = MESSAGE.getBytes();
        String argument = new BigInteger(bytes).toString(16);
        List<Parameter> inputs = Collections.singletonList(new Parameter("publicKey", BYTES_TYPE, argument));
        List<Parameter> outputs = Collections.emptyList();
        LinearChainTransaction init = (LinearChainTransaction) this.adapter.invokeSmartContract(smartContractPath, functionIdentifier, inputs, outputs, REQUIRED_CONFIDENCE, Long.MAX_VALUE).get();
        log.info("initial transaction {}", init.getTransactionHash());
        functionIdentifier = "getPublicKey";
        inputs = Collections.singletonList(new Parameter("ethereumAddress", ADDRESS_TYPE, "0x90645Dc507225d61cB81cF83e7470F5a6AA1215A"));
        outputs = Collections.singletonList(new Parameter("return", BYTES_TYPE, null));
        Transaction result = this.adapter.invokeSmartContract(smartContractPath, functionIdentifier, inputs, outputs, REQUIRED_CONFIDENCE, 0).get();
        String value = result.getReturnValues().get(0).getValue();
        log.debug(value);
        String retrievedMessage = new String(new BigInteger(value, 16).toByteArray(), StandardCharsets.UTF_8);
        Assertions.assertEquals(MESSAGE, retrievedMessage);
        log.debug(retrievedMessage);
    }

    @Test
    @Disabled
    void createNewKeystoreFile() throws CipherException, IOException {
        final String filePath = "C:\\Ethereum\\keystore";
        final File file = new File(filePath);
        final String password = "123456789";
        final String privateKey = "6871412854632d2ccd9c99901f5a0a3d838b31dbc6bfecae5f2382d6b7658bbf";
        ECKeyPair pair = ECKeyPair.create(new BigInteger(privateKey, 16));
        WalletUtils.generateWalletFile(password, pair, file, false);
    }

    @Test
    @Disabled
    void testBlockNumbers() throws IOException {
        LocalDateTime from = LocalDateTime.of(2019, 12, 27, 10, 50);
        LocalDateTime to = LocalDateTime.of(2019, 12, 27, 10, 56);
        long fromBlockNumber = this.adapter.getBlockAfterIsoDate(from);
        long toBlockNumber = this.adapter.getBlockAfterIsoDate(to) - 1;
        // sanity check
        Assertions.assertTrue((toBlockNumber - fromBlockNumber) * 12 < Duration.between(from, to).getSeconds() * 2);
        log.info("From: {} to: {}", fromBlockNumber, toBlockNumber);
    }

    @Test
    @Disabled
    void testExtremeBlockNumbers() throws IOException {
        LocalDateTime from = LocalDateTime.of(2001, 12, 27, 10, 50);
        LocalDateTime to = LocalDateTime.of(2029, 12, 27, 10, 56);
        long fromBlockNumber = this.adapter.getBlockAfterIsoDate(from);
        long toBlockNumber = this.adapter.getBlockAfterIsoDate(to);
        // sanity check
        Assertions.assertEquals(0, fromBlockNumber);
        Assertions.assertEquals(Long.MAX_VALUE, toBlockNumber);
        log.info("From: {} to: {}", fromBlockNumber, toBlockNumber);
    }

    Permissions deployContract() throws ExecutionException, InterruptedException, IOException {
        Permissions contract = Permissions.deploy(this.adapter.getWeb3j(), this.adapter.getCredentials(),
                new DefaultGasProvider()).sendAsync().get();
        Assertions.assertTrue(contract.isValid());

        return contract;
    }

    private EthereumAdapter getAdapter() {
        String nodeUrl = "http://localhost:7545/";
        URL url = Thread.currentThread().getContextClassLoader().getResource("UTC--2019-05-30T11-21-08.970000000Z--90645dc507225d61cb81cf83e7470f5a6aa1215a.json");
        File file = new File(url.getPath());
        String keystorePath = file.getPath();
        String keystorePassword = "123456789";
        double adversaryVotingRatio = 0.2;
        int pollingTimeSeconds = 2;
        EthereumAdapter ethereumAdapter = new EthereumAdapter(nodeUrl, pollingTimeSeconds, "");
        final PoWConfidenceCalculator cCalc = new PoWConfidenceCalculator();
        cCalc.setAdversaryRatio(adversaryVotingRatio);
        try {
            ethereumAdapter.setCredentials(keystorePassword, keystorePath);
        } catch (IOException | CipherException e) {
            e.printStackTrace();
        }
        ethereumAdapter.setConfidenceCalculator(cCalc);
        return ethereumAdapter;
    }
}