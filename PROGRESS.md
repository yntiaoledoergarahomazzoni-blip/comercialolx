# Estado atual do Portal LKX

Retomado em 22/10/2026 após solicitação do usuário. A marca na interface está como LKX; o logo foi removido da interface por enquanto.

## Concluído nesta retomada

- Finalizada a migração para ESM com `firebase-admin` 14.5.0.
- `package.json` agora declara `type: module` e Node.js 22+; o lockfile acompanha a versão mínima.
- Convertidos os pontos de entrada da API Vercel e o script de atribuição de administrador para imports modulares.
- Atualizados título, marca da interface, configurações padrão, `.env.example` e README para LKX.
- Mantida a tela de configuração pendente até conexão do Firebase.
- Verificadas sintaxes do backend, script de administração, entrypoint, adaptador frontend, JavaScript embutido no HTML e arquivos JSON.

## Pendente

- Conectar a conta/projeto Vercel e configurar as variáveis de produção.
- Publicar o portal e validar o login e o fluxo operacional no domínio de produção.

## Firebase conectado em 22/10/2026

- Configuração Web e credencial Firebase Admin preparadas localmente no `.env`; a chave de service account está ignorada pelo Git.
- Firestore do projeto `vendas-1eede` acessível pelo Firebase Admin SDK.
- UID administrativo `0c3odW9d0SN2tGRbOY8gXIvlv8x2` recebeu `admin: true`; claim confirmado por consulta ao Firebase.
- Usuário publicou `firestore.rules` pelo Console Firebase. Leitura/gravação direta pelo cliente segue negada.
- Firebase Storage não é usado. O cliente precisa selecionar foto e vídeo para avançar; o servidor valida os metadados e descarta-os sem persistência. O conteúdo não sai do navegador.
