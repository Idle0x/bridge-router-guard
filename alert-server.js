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
    console.log(`\n--- TELEMETRY PAYLOAD ---`);
    console.log(response_data);
    console.log('=============================================\n');

    res.status(200).json({ received: true });
});

app.listen(3000, () => {
    console.log('🛡️  Drosera Institutional Telemetry Server listening on port 3000...');
});
