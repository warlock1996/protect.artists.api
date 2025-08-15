-- Create VPNs table with description field
CREATE TABLE IF NOT EXISTS `vpns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `description` varchar(500) DEFAULT NULL COMMENT 'Description of the VPN service (max 500 characters)',
  `logo_path` varchar(500) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert VPN data
INSERT INTO `vpns` (`name`, `description`, `logo_path`) VALUES
("Surfshark", "Bien qu’il ne figure pas dans le classement ARCOM, Surfshark est extrêmement populaire en Europe et reconnu pour son excellent rapport qualité/prix, sa politique de connexions illimitées, et ses performances élevées en matière de streaming. Il est souvent recommandé par les utilisateurs expérimentés qui veulent un VPN multi-usage. Il fait donc partie de notre protocole comme VPN performant, mais sous-représenté dans les études classiques.", NULL),
("ExpressVPN", "ExpressVPN est mondialement reconnu pour sa fiabilité et sa rapidité, notamment pour les contenus streaming géorestreints. Malgré son absence dans le rapport ARCOM, il reste un acteur majeur du marché VPN, très utilisé par les internautes cherchant des performances maximales. Il est inclus dans les tests car il représente un choix premium fréquent chez les utilisateurs avertis.", NULL),
("NordVPN", "Présent dans le rapport ARCOM – 26 % des citations\nNordVPN est le VPN le plus cité dans le rapport ARCOM. Sa simplicité d'utilisation, sa compatibilité avec tous les appareils et ses fonctions anti-blocage avancées en font une référence absolue pour les internautes français. C’est un VPN incontournable à intégrer dans tout protocole de test.", NULL),
("Cyberghost VPN", "Présent dans le rapport ARCOM – 9 % des citations\nCyberghost est particulièrement populaire auprès des amateurs de streaming grâce à ses serveurs optimisés. Il représente un usage intermédiaire entre grand public et utilisateurs avertis. Sa présence reflète une utilisation fréquente en France pour contourner les blocages géographiques.", NULL),
("UrbanVPN", "UrbanVPN est un VPN entièrement gratuit basé sur un modèle pair-à-pair, très répandu malgré une réputation mitigée. Il est intégré dans notre protocole car il est facilement accessible, sans inscription, et couramment utilisé par les jeunes ou utilisateurs occasionnels pour tester des contournements de géorestrictions. Il ne figure pas dans le rapport ARCOM, mais représente une réalité d’usage.", NULL),
("Hola VPN", "Présent dans le rapport ARCOM – 5 % des citations\nHola VPN fonctionne également sur un modèle peer-to-peer. Il est massivement utilisé malgré ses failles de sécurité, en particulier chez les internautes cherchant un VPN sans inscription. Son inclusion permet d’évaluer les risques de contournement même via des solutions peu sécurisées.", NULL),
("Proton VPN", "Présent dans le rapport ARCOM – 7 % des citations\nProton VPN est apprécié pour sa politique de confidentialité stricte et son infrastructure suisse. Il attire les utilisateurs qui cherchent à la fois sécurité et contournement de blocage. Son offre gratuite performante en fait un VPN très utilisé par les internautes français, ce qui justifie sa place dans notre protocole.", NULL),
("Mullvad VPN", "Mullvad est très apprécié dans la communauté cybersecurity et vie privée, notamment pour son système d'inscription sans email et son paiement en cash ou crypto. Même s’il n’est pas dans le top ARCOM, il représente un usage avancé et anonyme du VPN que nous devons intégrer dans notre analyse globale.", NULL),
("Windscribe", "Présent dans le rapport ARCOM – 2 % des citations\nWindscribe combine une offre gratuite puissante, des fonctions techniques avancées (split tunneling, double-hop) et une interface simple. Il est utilisé par des internautes technophiles ou étudiants, ce qui en fait un acteur pertinent à suivre dans les usages concrets de contournement.", NULL),
("Hide.me", "Hide.me est un VPN discret mais fiable, souvent recommandé pour ses options de connexion sécurisées et ses protocoles avancés. Il est souvent utilisé par des internautes souhaitant tester différents serveurs sans engagement, notamment grâce à son plan gratuit. Sa présence dans les tests permet d'évaluer des usages plus spécialisés.", NULL);

