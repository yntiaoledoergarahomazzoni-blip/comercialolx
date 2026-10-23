# LKX · Portal de Operações

Portal responsivo para acompanhar as etapas posteriores a uma operação. Não possui checkout, cobrança, solicitação de pagamento ou captura de cartão.

## Estado do projeto

O frontend e uma API Node/Express usam Firebase Authentication e Firestore. As leituras e alterações passam pelo backend; as regras do Firestore negam acesso direto ao navegador. A etapa de embalagem exige que o cliente selecione uma foto e um vídeo no próprio aparelho. O servidor valida os metadados recebidos, descarta-os sem persistência e libera a próxima etapa automaticamente; os arquivos não são enviados nem ficam disponíveis à equipe. Chaves públicas são aleatórias, armazenadas somente como hash e exibidas uma única vez ao criar ou renovar.

**Firebase conectado:** Firestore, regras e conta administrativa estão configurados. Para colocar o portal no ar, conecte o projeto à Vercel e configure as variáveis de produção com os valores de `.env`, usando `FIREBASE_SERVICE_ACCOUNT_JSON` para a chave privada e `ACCESS_SESSION_SECRET` para a sessão. Não publique esses segredos em Git nem os envie pelo chat.

## Requisitos

- Node.js 24.x
- Projeto Firebase com Authentication (e-mail/senha) e Firestore Native
- Credencial de service account instalada fora do repositório para o backend

## Executar localmente

1. Instale dependências com `npm install`.
2. Configure `.env` com a configuração Web do Firebase e o Project ID. Não substitua o `.env` já preparado se estiver retomando uma configuração existente.
3. Guarde a chave JSON de service account em local privado, fora desta pasta, e configure `GOOGLE_APPLICATION_CREDENTIALS` com o caminho absoluto. Em hosts sem arquivos montados, use a variável secreta `FIREBASE_SERVICE_ACCOUNT_JSON`.
4. Gere `ACCESS_SESSION_SECRET` com pelo menos 32 bytes aleatórios. Exemplo: `node --input-type=commonjs -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"`.
5. Execute `npm run dev` e abra `http://localhost:3000`.

As variáveis Web do Firebase (`FIREBASE_API_KEY`, `FIREBASE_AUTH_DOMAIN`, `FIREBASE_PROJECT_ID`, `FIREBASE_APP_ID`) são configuração pública do cliente. A chave privada da service account e `ACCESS_SESSION_SECRET` são segredos de servidor e nunca devem ser publicados no frontend ou commitados.

## Configurar Firebase

1. No Firebase Console, crie o projeto e habilite Authentication com o provedor E-mail/Senha.
2. Crie o Firestore em modo Native. As coleções são criadas pela API à medida que os registros forem gravados: `operations`, `customers`, subcoleções `steps`, `history` e `messages`, `bank_details`, `pickup_addresses`, `delivery_partners`, `pickup_schedules`, `access_tokens` e `settings`.
3. As regras `firestore.rules` foram publicadas no projeto Firebase. Elas negam acesso direto ao cliente; a API usa Firebase Admin e valida cada sessão. O app não usa Cloud Storage.
4. Crie a conta administrativa em Authentication. Obtenha o UID e atribua o claim `admin: true` com `npm run admin:grant -- <uid>`. A conta precisa entrar novamente depois de receber o claim.
5. Configure as variáveis no ambiente de execução. `GET /api/health` informa quando Firebase e o segredo da sessão estão prontos.

O serviço Firestore será criado no primeiro uso, portanto não há etapa de migração de esquema para rodar. `firestore.indexes.json` está preparado para receber índices compostos quando novas consultas forem adicionadas.

### Etapa de foto e vídeo

O navegador verifica se uma foto JPEG/PNG/WEBP de até 10 MB e um vídeo MP4/MOV de até 50 MB foram selecionados. O conteúdo dos arquivos não sai do aparelho. O servidor valida nome, formato e tamanho durante a solicitação, não guarda esses metadados e libera o agendamento automaticamente; a equipe não recebe nem analisa os arquivos.

## Rotas

- `/acesso`: chave de acesso individual do cliente
- `/operacao`: sessão do cliente, protegida por cookie HttpOnly
- `/admin/login`: autenticação via Firebase Auth
- `/admin/dashboard`, `/admin/operacoes`, `/admin/operacoes/:id`, `/admin/entregadores`, `/admin/configuracoes`: painel administrativo

As APIs estão em `/api`. O cookie administrativo é criado pelo backend após verificar o ID token e o claim `admin`. A sessão do cliente tem validade limitada, SameSite Strict, HttpOnly, e valida a revogação do token a cada requisição. A tela do portal consulta atualizações de status periodicamente.

## Fluxo de uma operação

No painel, a equipe informa somente o valor disponível. O sistema cria as etapas e gera uma chave individual, exibida uma única vez. O cliente usa a chave em `/acesso` e preenche seus dados pessoais, bancários e o endereço para continuar.

## Deploy

O servidor Express pode ser publicado na Vercel (serverless), Cloud Run ou outro host Node compatível. Configure no provedor as variáveis de produção e use HTTPS. O Firebase hospeda Authentication e Firestore; este projeto não usa Cloud Storage nem depende de Functions.

Para Vercel, use `vercel.json` e defina as variáveis como Environment Variables do projeto. Salve o conteúdo da credencial JSON em `FIREBASE_SERVICE_ACCOUNT_JSON` como variável secreta; não o inclua nos arquivos publicados. Para um host Node persistente, use `npm start`. Nunca envie `.env`, chave de service account, tokens de sessão ou dados dos clientes para o Git.

Para domínio próprio, aponte o DNS para o host do portal, configure HTTPS e informe o domínio em `NEXT_PUBLIC_APP_URL`/`domain` (o projeto não precisa de IDs de operação nas URLs públicas). Envie sempre `/acesso` e a chave em canal separado.

## Dados e privacidade

- O Firestore não permite acesso direto pelo navegador. Todas as regras estão negadas por padrão.
- As operações recebem ID interno aleatório e número público aleatório independente.
- O token de acesso não é armazenado em texto; só seu hash SHA-256. A renovação revoga os tokens anteriores.
- A resposta do cliente inclui somente sua operação e dados necessários ao acompanhamento. Dados bancários e documentos ficam fora do payload do portal.
- Campos bancários ficam em coleção separada e só são servidos à API administrativa autenticada.
- Foto e vídeo são selecionados no navegador. O conteúdo e os metadados não são armazenados nem enviados à equipe.
- Mensagens, status e ações importantes são registrados no histórico.

## Limites de integração

O projeto usa o Firebase já configurado, mas não cria contas, não configura DNS e não envia WhatsApp, SMS ou e-mail. Essas integrações dependem das contas e credenciais do proprietário. Os dados demonstrativos antigos foram removidos do HTML publicado.

