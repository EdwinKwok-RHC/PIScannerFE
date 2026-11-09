# Deployment steps
Build Locally:
```bat
npm install
npm run build
```
Then ZIP the **contents** of `dist`, not the `dist` folder itself:
```powershell
Compress-Archive -Path .\dist\* -DestinationPath .\deploy.zip -Force
```
Then deploy directly:
```bat
az webapp deploy ^
--resource-group rg-documentintelligence-POC ^
--name app-Prompt-Scanner-FEOnly ^
--src-path deploy.zip ^
--type zip
```