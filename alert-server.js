const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/alerts', (req, res) => {
    const { trap_address, block_number, title, severity, labels, response_data } = req.body;

    console.log('\n=============================================');
    console.log('🚨 DROSERA CRITICAL SECURITY ALERT 🚨');
    console.log('=============================================');
    console.log(`[!] Title:    ${title}`);
    console.log(`[!] Severity: ${severity.toUpperCase()}`);
    console.log(`[!] Trap:     ${trap_address}`);
    console.log(`[!] Block:    ${block_number}`);
    console.log(`[!] Labels:   `, labels);
    
    // Unpack the specific AlertData payload from the trap
    console.log(`\n--- TELEMETRY PAYLOAD ---`);
    if (response_data) {
        console.log(`Vault Drain Velocity:  ${response_data.vaultDrainVelocity || 0}`);
        console.log(`Phantom Mint Velocity: ${response_data.phantomMintVelocity || 0}`);
        console.log(`Router Spoofed:        ${response_data.routerSpoofed ? 'YES (CRITICAL)' : 'NO'}`);
    } else {
        console.log('No specific response_data attached.');
    }
    console.log('=============================================\n');

    res.status(200).json({ received: true });
});

app.listen(3000, () => {
    console.log('🛡️  Drosera Institutional Telemetry Server listening on port 3000...');
});
