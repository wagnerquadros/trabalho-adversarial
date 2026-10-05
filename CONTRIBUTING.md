# Como contribuir

A nota do trabalho é individual e medida pelos commits de cada integrante (enunciado, §5). Por isso, cada pessoa trabalha na própria branch e entra na `main` por pull request.

## Fluxo

1. Atualize a sua branch com a `main` antes de começar:

   ```bash
   git switch <sua-branch>
   git pull origin main
   ```

2. Faça commits pequenos, um por mudança lógica, citando a issue do quadro (`Refs #N`).
3. Abra um pull request para a `main`. O revisor indicado na issue aprova antes do merge.
4. No quadro do projeto, mova a issue para "In progress" ao começar e para "Done" ao fechar.

## Commits que contam

O e-mail do git precisa ser um e-mail cadastrado na sua conta do GitHub; caso contrário, o commit não é atribuído a você. Confira com:

```bash
git log --format='%an <%ae>' | sort -u
```

## Formatação

Antes de abrir o pull request, formate os arquivos Markdown:

```bash
npx prettier --check README.md CONTRIBUTING.md fontes/referencias.md
```
