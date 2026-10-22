const express = require('express');
const cors = require('cors');
const axios = require('axios');
const https = require('https');
const { URL } = require('url');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Função auxiliar para consultar o VirusTotal com Base64URL correto
async function checkUrlReputation(targetUrl) {
    if (!process.env.VIRUSTOTAL_API_KEY) {
        return { status: 'Chave de API não configurada' };
    }

    try {
        const urlId = Buffer.from(targetUrl)
            .toString('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');

        const response = await axios.get(
            `https://www.virustotal.com/api/v3/urls/${urlId}`,
            {
                headers: {
                    'x-apikey': process.env.VIRUSTOTAL_API_KEY
                }
            }
        );

        const attributes = response.data.data.attributes;
        const stats = attributes.last_analysis_stats;
        const results = attributes.last_analysis_results;

        // Filtrar apenas os motores que deram como 'malicious' ou 'suspicious'
        const detectedThreats = [];
        for (const engineName in results) {
            const analysis = results[engineName];
            if (analysis.category === 'malicious' || analysis.category === 'suspicious') {
                detectedThreats.push({
                    engine: engineName,
                    category: analysis.category,
                    result: analysis.result // Ex: 'phishing', 'malware'
                });
            }
        }

        return {
            stats: stats,
            threats: detectedThreats // Lista detalhada com as ameaças encontradas
        };

    } catch (error) {
        if (error.response && error.response.status === 404) {
            try {
                const params = new URLSearchParams();
                params.append('url', targetUrl);
                
                await axios.post(
                    'https://virustotal.com/api/v3/urls',
                    params,
                    {
                        headers: {
                            'x-apikey': process.env.VIRUSTOTAL_API_KEY,
                            'content-type': 'application/x-www-form-urlencoded'
                        }
                    }
                );
             
                return { message: 'URL nova! Enviada para análise no VirusTotal.' };
            } catch (submitError) {
                console.error('Erro ao submeter URL:', submitError.message);
                return { error: 'A URL não estava catalogada e falhou ao tentar enviá-la para análise.'}
            }
        }
        console.error('Erro na API VirusTotal:', error.message);
        return { error: 'Não foi possível obter a reputação no VirusTotal.' };
    }
}

// Função auxiliar para verificar o certificado SSL/TLS
function checkSSL(hostname) {
    return new Promise((resolve) => {
        const req = https.request({
            hostname: hostname,
            port: 443,
            method: 'GET',
            rejectUnauthorized: true
        }, (res) => {
            resolve({ valid: true, message: 'Certificado SSL/TLS válido.' });
        });

        req.on('error', (err) => {
            resolve({ valid: false, message: `Erro SSL/TLS: ${err.message}` });
        });

        req.end();
    });
}

// Rota principal (Barra '/' corrigida aqui)
app.post('/api/scan', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL não fornecida.' });
    }

    try {
        const parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);

        // Executa as verificações
        const sslStatus = await checkSSL(parsedUrl.hostname);
        const externalAnalysis = await checkUrlReputation(parsedUrl.href);

        return res.json({
            target: parsedUrl.href,
            domain: parsedUrl.hostname,
            ssl: sslStatus,
            reputation: externalAnalysis,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        return res.status(400).json({ error: 'Formato de URL inválido.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));