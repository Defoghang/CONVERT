# CONVERT Telegram Bot

Bot Telegram professionnel avec capacite de cassage de hashes via John the Ripper.

## Fonctionnalites

- Commandes : /start, /help, /echo, /stats, /status, /broadcast
- Cassage de hashes : /crack <hash> (admin uniquement)
- Informations John : /johninfo (admin uniquement)
- Verification wordlist : /testwordlist (admin uniquement)
- Base de donnees SQLite pour la persistance
- Rate limiting integre
- Journalisation avec rotation
- Tests unitaires avec pytest

## Commandes admin

### /crack

