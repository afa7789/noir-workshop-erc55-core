# Workshop Noir: Tutorial Completo

Este tutorial ensina como usar Noir, uma linguagem de domínio específico (DSL) para construir circuitos zero-knowledge. Noir compila para R1CS (Rank-1 Constraint System) e permite criar provas SNARK de forma eficiente. Documento baseado na apresentação feita por [zkpedro](https://github.com/signorecello). Eu tive que expandir um pouco o que foi explicado no workshop para conseguir entender alguns conceitos que passaram rápido na apresentação, portanto esse repositório e principalmente o README são feitos para consultas futuras sobre o assunto.

## Índice

1. [Pré-requisitos](#pré-requisitos)
2. [Configuração do Ambiente](#configuração-do-ambiente)
3. [Estrutura do Projeto](#estrutura-do-projeto)
4. [Anatomia do Circuito](#anatomia-do-circuito)
5. [Comandos Essenciais](#comandos-essenciais)
6. [Geração e Verificação de Provas](#geração-e-verificação-de-provas)
7. [Integração com Ethereum](#integração-com-ethereum)
8. [Recursos Avançados](#recursos-avançados)

## Pré-requisitos

- Sistema Unix-like (macOS, Linux, ou Windows com WSL2)
- Node.js 18+ (para integração com JavaScript/TypeScript)
- Git
- Conhecimento básico de criptografia e zero-knowledge

## Configuração do Ambiente

### Instalação via Gerenciadores de Versão

```bash
# Instalar noirup
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
source ~/.bashrc

# Instalar bbup para Barretenberg
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
source ~/.bashrc

# Instalar versões mais recentes
noirup
bbup
```

### Verificação da Instalação

```bash
nargo --version
bb --version
```

## Estrutura do Projeto

```
workshop/
├── Nargo.toml          # Manifesto do projeto
├── Prover.toml         # Inputs privados do witness
├── Verifier.toml       # Inputs públicos (opcional)
├── src/
│   └── main.nr         # Circuito principal
└── target/             # Artefatos de compilação
    ├── workshop.json   # Circuito compilado (R1CS)
    └── workshop.gz     # Witness comprimido
```

Os arquivos `.toml` são configurações para execução e teste local do circuito. O `Prover.toml` contém todos os inputs (privados e públicos) que o provador forneceria ao circuito, sendo usado pelos comandos nargo execute e nargo test para simular a execução durante desenvolvimento. O `Verifier.toml` (opcional) contém apenas os inputs públicos, separando claramente o que é visível ao verificador. Estes arquivos são apenas para desenvolvimento e debug - na produção real, os inputs vêm da aplicação (JavaScript, Rust, etc.) que chama o circuito programaticamente, não dos arquivos `.toml`.

## Anatomia do Circuito

### Circuito Base (`src/main.nr`)

```noir
fn main(x: Field, y: pub Field) {
    assert(x != y);
}
```

**Análise Técnica:**
- `Field`: Elemento do campo primo BN254 (ordem ~2^254)
- `pub`: Marca input como público (constraint público)
- `assert`: Cria constraint R1CS que deve ser satisfeita
- Função `main` define o ponto de entrada do circuito

### Configuração de Inputs (`Prover.toml`)

```toml
x = "0x01"  # Input privado (witness)
y = "0x02"  # Input público
```

### Manifesto do Projeto (`Nargo.toml`)

```toml
[package]
name = "workshop"
type = "bin"
authors = [""]
compiler_version = ">=0.19.0"

[dependencies]
```

## Comandos Essenciais

### Desenvolvimento

```bash
# Verificar sintaxe sem compilação completa
nargo check

# Executar testes unitários
nargo test

# Executar circuito e gerar witness
nargo execute

# Compilar para R1CS
nargo compile
```

### Depuração

```bash
# Executar com debug
nargo execute --print-witness

# Mostrar informações do circuito
nargo info
```

## Geração e Verificação de Provas

### Prover (Geração da Prova)

```bash
# 1. Gerar witness
nargo execute

# 2. Compilar circuito
nargo compile

# 3. Gerar prova PLONK
bb prove -b ./target/workshop.json \
         -w ./target/workshop.gz \
         -o ./target \
         --output_format bytes_and_fields \
         --oracle_hash keccak
```

### Opções de Hash Disponíveis (`--oracle_hash`)

```bash
# Keccak-256 (recomendado para Ethereum)
bb prove --oracle_hash keccak ...

# Blake2s (mais rápido, menor compatibilidade)
bb prove --oracle_hash blake2s ...

# Blake3 (mais moderno, ainda experimental)
bb prove --oracle_hash blake3 ...

# SHA-256 (padrão, compatibilidade universal)  
bb prove --oracle_hash sha256 ...

# Poseidon (otimizado para ZK circuits)
bb prove --oracle_hash poseidon ...
```

**Comparação de Hashes:**

| Hash | Velocidade | Gas Cost (ETH) | ZK-Friendly | Uso Recomendado |
|------|------------|----------------|-------------|-----------------|
| `keccak` | Média | Baixo | Não | **Produção ETH** |
| `blake2s` | Rápido | Alto | Sim | Desenvolvimento |
| `blake3` | Muito rápido | Alto | Sim | Experimental |
| `sha256` | Lento | Médio | Não | Cross-chain |
| `poseidon` | Médio | N/A | **Sim** | **ZK-native apps** |

### Formatos de Prova (`--output_format`)

```bash
# Formato otimizado para Ethereum (recomendado)
--output_format bytes_and_fields

# Formato apenas bytes (compatibilidade)
--output_format bytes

# Formato apenas fields (debugging)
--output_format fields

# Formato JSON (human-readable, debugging)
--output_format json

# Formato compacto (menor tamanho)
--output_format compact
```

**Estruturas Geradas por Formato:**

#### `bytes_and_fields` (Produção)
```bash
target/
├── proof              # Prova binária otimizada (~2KB)
├── public_inputs      # Inputs públicos em formato field
└── verification_key   # Chave de verificação
```

#### `json` (Debugging)
```json
{
  "proof": {
    "a": ["0x...", "0x..."],
    "b": ["0x...", "0x..."], 
    "c": ["0x...", "0x..."],
    "z": "0x...",
    "t_lo": "0x...",
    "t_mid": "0x...",
    "t_hi": "0x..."
  },
  "public_inputs": ["0x02"]
}
```

### Sistemas de Prova (Backends)

Noir utiliza diferentes backends de prova (proving systems) do Barretenberg para gerar SNARKs. Cada backend implementa variações otimizadas do protocolo PLONK, oferecendo trade-offs entre velocidade de geração, tamanho da prova e compatibilidade. A escolha do backend impacta diretamente a performance e onde as provas podem ser verificadas. Um sistema de prova é um protocolo criptográfico que permite a um provador demonstrar conhecimento de uma informação secreta (como uma senha, chave privada, ou solução de um problema) para um verificador, sem revelar a informação em si.

#### UltraPlonk vs UltraHonk vs MegaHonk

```bash
# UltraPlonk (padrão, estável)
bb prove --scheme ultra_plonk ...

# UltraHonk (mais eficiente, novo padrão)
bb prove --scheme ultra_honk ...

# MegaHonk (Aztec-specific, experimental)
bb prove --scheme mega_honk ...
```

**Comparação Detalhada dos Backends:**

| Backend | Prova Size | Proving Time | Verifying Time | Solidity Support | Status |
|---------|------------|--------------|----------------|------------------|---------|
| **UltraPlonk** | ~2.5KB | 100% | 100% | ✅ | Legacy/Estável |
| **UltraHonk** | ~2KB | **30% faster** | **50% faster** | ✅ | **Recomendado** |
| **MegaHonk** | ~1.5KB | **50% faster** | **70% faster** | ❌ | Aztec-only |

#### O que é UltraHonk?

UltraHonk é uma versão otimizada do sistema de prova PLONK que oferece geração de provas significativamente mais rápida. Principais diferenças:

**UltraHonk Características:**
- **Sumcheck Protocol**: Usa protocolos de sumcheck mais eficientes
- **Parallelização**: Melhor suporte para processamento paralelo  
- **Memory Layout**: Layout de memória otimizado
- **Polynomial Commitments**: Esquemas de commitment mais eficientes
- Suporte completo para geração de contratos Solidity verificadores

**Quando Usar Cada Backend:**

```bash
# Produção Ethereum (recomendado 2024+)
bb prove --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields

# Desenvolvimento/Debug  
bb prove --scheme ultra_plonk --oracle_hash blake2s --output_format json

# Máxima Performance (sem Ethereum)
bb prove --scheme mega_honk --oracle_hash poseidon --output_format compact
```

#### Migração de UltraPlonk para UltraHonk

**Diferenças na Compilação:**
```bash
# UltraPlonk (método antigo)
nargo compile
bb prove --scheme ultra_plonk -b target/workshop.json -w target/workshop.gz -o target

# UltraHonk (método atual - RECOMENDADO)
nargo compile
bb prove --scheme ultra_honk -b target/workshop.json -w target/workshop.gz -o target

# Geração de contrato Solidity (UltraHonk tem suporte oficial)
bb write_solidity_verifier --scheme ultra_honk -b target/workshop.json -o target/VerifierContract.sol
```

**Importante:** Apenas UltraHonk tem suporte oficial para geração de contratos Solidity verificadores.

#### Sistemas de prova ZK **não contemplados por Noir:**

Noir foca em PLONK/UltraPlonk/Honk por serem universais, balanceados e com boa compatibilidade Ethereum, mas cada sistema tem seus nichos específicos.

##### SNARKs Alternativos

**Groth16**
- Verificação mais rápida e menor tamanho de prova, mas requer trusted setup específico para cada circuito
- Frameworks: Circom, libsnark, arkworks
- Trade-off: Setup por circuito vs provas menores

**Halo2** 
- Sistema recursivo sem trusted setup da Zcash
- Permite provas recursivas (provas de provas) sem trusted setup inicial
- Framework próprio com sintaxe diferente do Noir

**Marlin**
- Universal setup como PLONK, mas com provas 4x-6x maiores que Groth16
- Alternativa ao PLONK para alguns casos

##### STARKs
**zk-STARKs**
- Mais rápidos que SNARKs e Bulletproofs, sem trusted setup
- Provas maiores, mas quantum-resistant
- Frameworks: Cairo (StarkNet), RISC Zero, Winterfell

##### Bulletproofs
- Sem trusted setup, mas verificação mais lenta que SNARKs
- Provas menores que STARKs mas verificação não-escalável para blockchain
- Ideal para range proofs e casos específicos

##### Sistemas Especializados

**FRI-based** (Fast Reed-Solomon Interactive Oracle Proofs)
- Base dos STARKs modernos
- RISC Zero, Polygon Zero

**Nova/SuperNova**
- Sistemas recursivos experimentais
- Folding schemes

**GKR-based**
- Para computações específicas
- Menos generalistas

##### Não é necessário o arquivo de Power of Tau

o Noir você não precisa do arquivo de cerimônia (como o powersOfTau28_hez_final_XX.ptau do Circom) porque ele usa sistemas de prova universais.
Diferença Fundamental:
Circom + Groth16 (precisa de cerimônia):

Circuit-specific setup: Cada circuito precisa de sua própria cerimônia
Trusted setup específico gera chaves de verificação únicas
Arquivos .ptau contêm "poderes de tau" para a cerimônia

Noir + PLONK/UltraHonk (não precisa):

Universal setup: Uma única cerimônia serve para todos os circuitos
SRS (Structured Reference String) é reutilizável
O Barretenberg já vem com o setup universal embutido

**Por Que?**
PLONK/UltraHonk foram projetados para serem universais - a mesma "cerimônia" funciona para qualquer circuito, eliminando a necessidade de downloads e setups específicos. Isso torna o desenvolvimento muito mais simples e seguro.
Resumo: Noir abstrai completamente a complexidade das cerimônias porque usa sistemas de prova que precisam apenas de um setup universal já incluído na ferramenta.

### Configurações Recomendadas por Caso de Uso

#### Browser/Client-Side Proving
```bash
# Configuração otimizada para browser
bb prove --scheme ultra_honk \
         --oracle_hash blake2s \
         --output_format compact \
         --threads auto
```

Para proving no browser, UltraHonk é significativamente mais rápido. Em um M1 MacBook Air, uma assinatura pode ser provada em menos de 3 segundos com UltraHonk e multithreading habilitado.

#### Produção Ethereum (Recomendado)
```bash  
# Configuração balanceada para produção
bb prove --scheme ultra_honk \
         --oracle_hash keccak \
         --output_format bytes_and_fields
```

#### Alta Performance (não-Ethereum)
```bash
# Máxima velocidade para aplicações nativas
bb prove --scheme mega_honk \
         --oracle_hash poseidon \
         --output_format compact
```

### Verifier (Verificação da Prova)

```bash
# 1. Gerar verification key
bb write_vk -b target/workshop.json -o target --oracle_hash keccak

# 2. Verificar prova
bb verify --oracle_hash keccak
```

### Explicação dos Parâmetros

- `--oracle_hash keccak`: Usa Keccak-256 para hashing em oráculos
- `--output_format bytes_and_fields`: Formato otimizado para Ethereum
- `-b`: Bytecode do circuito (R1CS compilado)
- `-w`: Witness (assignment das variáveis)
- `-o`: Diretório de saída

## Integração com Ethereum

### Processo Completo de Geração do Contrato Verificador

#### 1. Preparação dos Artefatos

Antes de gerar o contrato Solidity, certifique-se de ter os artefatos necessários:

```bash
# Compilar o circuito
nargo compile

# Gerar a verification key
bb write_vk -b target/workshop.json -o target --oracle_hash keccak
```

#### 2. Geração do Contrato Solidity

```bash
# Gerar contrato verificador Solidity
bb write_solidity_verifier -b target/workshop.json -o target/VerifierContract.sol --oracle_hash keccak
```

**Parâmetros explicados:**
- `-b target/workshop.json`: Bytecode do circuito compilado
- `-o target/VerifierContract.sol`: Caminho de saída do contrato
- `--oracle_hash keccak`: Função hash consistente com a prova

#### 3. Estrutura do Contrato Gerado

O contrato gerado terá aproximadamente esta estrutura:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.4;

contract UltraVerifier {
    uint256 constant N_LOK = 4;
    uint256 constant N_INV = 5;
    // ... outras constantes específicas do circuito
    
    struct VerificationKey {
        uint256 circuit_size;
        uint256 num_inputs;
        uint256 work_root;
        uint256 domain_inverse;
        uint256[] q_m;
        uint256[] q_l;
        uint256[] q_r;
        uint256[] q_o;
        uint256[] q_c;
        // ... outros componentes da chave
    }
    
    function loadVerificationKey() internal pure returns (VerificationKey memory) {
        // Chave de verificação hardcoded específica do circuito
    }
    
    function verify(bytes memory proof, bytes32[] memory publicInputs) 
        public view returns (bool) {
        // Implementação da verificação PLONK
        return verifyProof(proof, publicInputs);
    }
    
    function verifyProof(bytes memory proof, bytes32[] memory publicInputs) 
        internal view returns (bool) {
        // Lógica de verificação usando pairing checks
    }
}
```

#### 4. Preparação da Prova para Blockchain

```bash
# Gerar prova no formato correto
bb prove -b ./target/workshop.json \
         -w ./target/workshop.gz \
         -o ./target \
         --output_format bytes_and_fields \
         --oracle_hash keccak

# Converter prova para formato hexadecimal
xxd -p target/proof | tr -d '\n' > target/proof.hex

# Ou usando od (alternativa)
cat ./target/proof | od -An -v -t x1 | tr -d ' \n' > target/proof.hex
```

#### 5. Extrair Inputs Públicos

```bash
# Extrair inputs públicos da prova
bb proof_as_fields -p target/proof -o target/public_inputs.json
```

### Deploy e Uso do Contrato

#### 1. Deploy via Hardhat/Foundry

```javascript
// hardhat deploy script
const { ethers } = require("hardhat");

async function main() {
    const VerifierFactory = await ethers.getContractFactory("UltraVerifier");
    const verifier = await VerifierFactory.deploy();
    await verifier.deployed();
    
    console.log("Verifier deployed to:", verifier.address);
}
```

#### 2. Interação com o Contrato

```javascript
// Exemplo completo de verificação
const fs = require('fs');
const { ethers } = require('hardhat');

async function verifyProof() {
    // Carregar artefatos
    const proofHex = fs.readFileSync('target/proof.hex', 'utf8');
    const publicInputs = JSON.parse(fs.readFileSync('target/public_inputs.json', 'utf8'));
    
    // Conectar ao contrato
    const verifier = await ethers.getContractAt("UltraVerifier", VERIFIER_ADDRESS);
    
    // Preparar inputs
    const proof = "0x" + proofHex;
    const publicInputsFormatted = publicInputs.map(input => 
        ethers.utils.hexZeroPad("0x" + input, 32)
    );
    
    // Verificar prova
    const isValid = await verifier.verify(proof, publicInputsFormatted);
    console.log("Proof is valid:", isValid);
    
    return isValid;
}
```

#### 3. Integração com Frontend

```javascript
// React/Web3 integration
import { ethers } from 'ethers';

const verifyOnChain = async (proof, publicInputs) => {
    const provider = new ethers.providers.Web3Provider(window.ethereum);
    const signer = provider.getSigner();
    
    const verifierContract = new ethers.Contract(
        VERIFIER_ADDRESS,
        VERIFIER_ABI,
        signer
    );
    
    try {
        const tx = await verifierContract.verify(proof, publicInputs);
        const receipt = await tx.wait();
        return receipt.status === 1;
    } catch (error) {
        console.error("Verification failed:", error);
        return false;
    }
};
```

### Otimizações e Considerações

#### Gas Optimization

```solidity
// Exemplo de wrapper para otimizar gas
contract OptimizedVerifier {
    UltraVerifier immutable verifier;
    
    constructor(address _verifier) {
        verifier = UltraVerifier(_verifier);
    }
    
    // Cache de provas verificadas para evitar re-verificação
    mapping(bytes32 => bool) public verifiedProofs;
    
    function verifyAndCache(bytes memory proof, bytes32[] memory publicInputs) 
        external returns (bool) {
        bytes32 proofHash = keccak256(abi.encodePacked(proof, publicInputs));
        
        if (verifiedProofs[proofHash]) {
            return true;
        }
        
        bool isValid = verifier.verify(proof, publicInputs);
        if (isValid) {
            verifiedProofs[proofHash] = true;
        }
        
        return isValid;
    }
}
```

#### Batch Verification

```solidity
// Para múltiplas provas
function batchVerify(
    bytes[] memory proofs, 
    bytes32[][] memory publicInputsArray
) external view returns (bool[] memory) {
    bool[] memory results = new bool[](proofs.length);
    
    for (uint i = 0; i < proofs.length; i++) {
        results[i] = verify(proofs[i], publicInputsArray[i]);
    }
    
    return results;
}
```

### Debugging e Troubleshooting

#### Erros Comuns

**1. "Invalid proof format"**
```bash
# Verificar se a prova foi gerada corretamente
file target/proof  # Deve mostrar: data

# Verificar tamanho da prova
ls -la target/proof  # Tamanho típico: ~2KB para circuitos simples
```

**2. "Public inputs mismatch"**
```bash
# Verificar inputs públicos extraídos
cat target/public_inputs.json

# Comparar com Prover.toml
grep "pub" src/main.nr  # Identificar quais são públicos
```

**3. "Gas limit exceeded"**
```javascript
// Aumentar gas limit para verificação
const tx = await verifier.verify(proof, publicInputs, {
    gasLimit: 500000  // Ajustar conforme necessário
});
```

### Automatização com Scripts

```bash
#!/bin/bash
# deploy_verifier.sh

set -e

echo "Generating Solidity verifier..."
bb write_solidity_verifier -b target/workshop.json -o target/VerifierContract.sol --oracle_hash keccak

echo "Preparing proof for blockchain..."
cat ./target/proof | od -An -v -t x1 | tr -d ' \n' > target/proof.hex

echo "Extracting public inputs..."
bb proof_as_fields -p target/proof -o target/public_inputs.json

echo "Verifier contract ready for deployment!"
echo "Contract: target/VerifierContract.sol"
echo "Proof hex: target/proof.hex"
echo "Public inputs: target/public_inputs.json"
```

## Recursos Avançados

### Tipos de Dados Avançados

```noir
fn main(
    hash_input: [u8; 32],     // Array de bytes
    merkle_root: Field,       // Root da Merkle tree
    nullifier: pub Field      // Nullifier público
) {
    // Verificar hash
    let computed_hash = std::hash::keccak256(hash_input);
    assert(computed_hash == merkle_root);
    
    // Constraint de nullifier único
    assert(nullifier != 0);
}
```

### Importação de Bibliotecas

```noir
use std::hash::keccak256;
use std::merkle::check_membership;
use std::ecdsa_secp256k1::verify_signature;
```

### Estruturas Condicionais

```noir
fn main(condition: bool, x: Field, y: Field) {
    let result = if condition { x } else { y };
    assert(result != 0);
}
```

## Debugging e Otimização

### Análise de Constraints

```bash
# Mostrar número de constraints
nargo info

# Detailed constraint breakdown
nargo compile --show-ssa
```

### Profile de Performance

```bash
# Timing de compilação
time nargo compile

# Timing de execução
time nargo execute
```

## Casos de Uso Comuns

### 1. Proof of Knowledge (PoK)
- Provar conhecimento de preimagem de hash
- Provar posse de chave privada

### 2. Range Proofs
- Provar que valor está dentro de intervalo
- Sem revelar o valor exato

### 3. Membership Proofs
- Provar pertencimento a conjunto
- Merkle tree membership

### 4. Identity e Privacy
- Zero-knowledge authentication
- Private voting systems

## Próximos Passos

1. **Circuitos Complexos**: Implementar Merkle trees, assinaturas digitais
2. **Bibliotecas**: Explorar `std::` library do Noir
3. **Integração Full-Stack**: Conectar com frontend React/Vue
4. **Otimização**: Reduzir número de constraints
5. **Auditoria**: Análise de segurança dos circuitos

## Recursos de Referência

- **Documentação**: https://noir-lang.org/docs
- **Exemplos**: https://github.com/noir-lang/noir-examples  
- **Biblioteca Padrão**: https://noir-lang.org/docs/standard_library
- **Discord**: https://discord.gg/aztec-protocol
- **Especificação PLONK**: https://eprint.iacr.org/2019/953

## Troubleshooting

### Erros Comuns

**Constraint não satisfeita:**
```
Error: Assertion failed: 'x != y'
```
Solução: Verificar inputs no `Prover.toml`

**Overflow aritmético:**
```
Error: Attempt to add with overflow
```
Solução: Usar tipos apropriados ou operações modulares

**Compilation failed:**
```
Error: Cannot find function 'unknown_function'
```
Solução: Verificar imports e nomes de funções
