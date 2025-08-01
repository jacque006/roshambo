import { RoshamboGame } from "../src/artifacts/RoshamboGame.js"
import { createLogger, PXE, Logger, SponsoredFeePaymentMethod, Fr } from "@aztec/aztec.js";
import { setupPXE } from "../src/utils/setup_pxe.js";
import { getSponsoredFPCInstance } from "../src/utils/sponsored_fpc.js";
import { SponsoredFPCContract } from "@aztec/noir-contracts.js/SponsoredFPC";
import { deploySchnorrAccount } from "../src/utils/deploy_account.js";

async function main() {

    let pxe: PXE;
    let logger: Logger;

    logger = createLogger('aztec:aztec-starter');

    pxe = await setupPXE();

    const sponsoredFPC = await getSponsoredFPCInstance();
    await pxe.registerContract({ instance: sponsoredFPC, artifact: SponsoredFPCContract.artifact });
    const sponsoredPaymentMethod = new SponsoredFeePaymentMethod(sponsoredFPC.address);

    let accountManager = await deploySchnorrAccount(pxe);
    const wallet = await accountManager.getWallet();
    const address = accountManager.getAddress();

    const votingContract = await RoshamboGame.deploy(wallet, address).send({ fee: { paymentMethod: sponsoredPaymentMethod } }).deployed();
    logger.info(`Voting Contract deployed at: ${votingContract.address}`);
}

main();
