# blockchain-access-layer-ethereum-plugin

### Running a Local geth Node

A geth node is used to access the Ethereum network. For development purposes, it is advised not to connect to the main
Ethereum network, but rather to one of the testnets.
(another, more difficult option would be to run a local private Ethereum network). In order to connect a geth node
to [Rinkeby](https://www.rinkeby.io) (one of Ethereum testnets), you can follow these steps:

1. [Install geth](https://github.com/ethereum/go-ethereum/wiki/Installing-Geth):
   this differs depending on your operating system.
2. Run geth in the fast-sync mode: This option downlaoads the whole blockchain but does not re-execute all transactions.
   Syncing the whole testnet blockchain (which is done once only) takes about 1-4 hours (depending on the hardware, the
   speed of the network connection, and the availability of peers). To start a geth node in the fast-sync mode, execute
   the following command:
    ```
    geth --rpcapi personal,db,eth,net,web3 --rpc --rinkeby --cache=2048 --rpcport "8545"
    --bootnodes=
    enode://a24ac7c5484ef4ed0c5eb2d36620ba4e4aa13b8c84684e1b4aab0cebea2ae45cb4d375b77eab56516d34bfbd3c1a833fc51296ff084b770b94fb9028c4d25ccf@52.169.42.101:30303,
    enode://343149e4feefa15d882d9fe4ac7d88f885bd05ebb735e547f12e12080a9fa07c8014ca6fd7f373123488102fe5e34111f8509cf0b7de3f5b44339c9f25e87cb8@52.3.158.184:30303,
    enode://b6b28890b006743680c52e64e0d16db57f28124885595fa03a562be1d2bf0f3a1da297d56b13da25fb992888fd556d4c1a27b1f39d531bde7de1921c90061cc6@159.89.28.211:30303
    ``` 
   If you want your node to be accessible remotely, apart from configuring your firewall, you also need to use the
   following extra option, when running the node: ```--rpcaddr "0.0.0.0"```
3. Test connection: you can test your connection to a running geth node using the following command
   (make sure to install geth on the computer where you run this command):```geth attach http://localhost:8545```
   please replace _localhost_ with the ip address of the computer running the node.
