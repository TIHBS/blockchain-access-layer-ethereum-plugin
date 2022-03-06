/*******************************************************************************
 * Copyright (c) 2022 Institute for the Architecture of Application System - University of Stuttgart
 * Author: Akshay Patel
 *
 * This program and the accompanying materials are made available under the
 * terms the Apache Software License 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

package blockchains.iaas.uni.stuttgart.de.plugin.ethereum;

import blockchains.iaas.uni.stuttgart.de.api.IAdapterExtension;
import blockchains.iaas.uni.stuttgart.de.api.interfaces.BlockchainAdapter;
import blockchains.iaas.uni.stuttgart.de.api.utils.PoWConfidenceCalculator;
import org.pf4j.Extension;
import org.pf4j.Plugin;
import org.pf4j.PluginWrapper;
import org.web3j.crypto.CipherException;

import java.io.IOException;
import java.util.Map;

public class EthereumPlugin extends Plugin {
    public EthereumPlugin(PluginWrapper wrapper) {
        super(wrapper);
    }

    @Override
    public void start() {
        super.start();
    }

    @Override
    public void stop() {
        super.stop();
    }

    @Extension
    public static class EthAdapterImpl implements IAdapterExtension {

        @Override
        public BlockchainAdapter getAdapter(Map<String, Object> parameters) {
            String nodeUrl = (String) parameters.get("nodeUrl");
            String keystorePassword = (String) parameters.get("keystorePassword");
            String keystorePath = (String) parameters.get("keystorePath");
            double adversaryVotingRatio = (double) parameters.get("adversaryVotingRatio");

            int pollingTimeSeconds = (int) parameters.get("pollingTimeSeconds");
            final EthereumAdapter adapter = new EthereumAdapter(nodeUrl, pollingTimeSeconds);

            final PoWConfidenceCalculator cCalc = new PoWConfidenceCalculator();
            cCalc.setAdversaryRatio(adversaryVotingRatio);

            try {
                adapter.setCredentials(keystorePassword, keystorePath);
            } catch (IOException | CipherException e) {
                e.printStackTrace();
            }

            adapter.setConfidenceCalculator(cCalc);
            return adapter;
        }

        @Override
        public String getBlockChainId() {
            return "ethereum";
        }

    }
}
