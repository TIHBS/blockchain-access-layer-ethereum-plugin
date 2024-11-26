package blockchains.iaas.uni.stuttgart.de.plugin.ethereum;

import blockchains.iaas.uni.stuttgart.de.api.utils.PoWConfidenceCalculator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;

class EthereumConnectionProfileTest {

    @Test
    void getIdentity() {
        EthereumConnectionProfile profile = new EthereumConnectionProfile();
        String nodeUrl = "http://localhost:8545/";
        URL url = Thread.currentThread().getContextClassLoader().getResource("UTC--2019-05-30T11-21-08.970000000Z--90645dc507225d61cb81cf83e7470f5a6aa1215a.json");
        profile.setKeystorePath(new File(url.getPath()).getPath());
        profile.setKeystorePassword("123456789");
        Assertions.assertEquals("0x90645dc507225d61cb81cf83e7470f5a6aa1215a", profile.getIdentity().toLowerCase());
    }
}