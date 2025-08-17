-- Create infringing_urls table for storing reported copyright infringement URLs
CREATE TABLE IF NOT EXISTS `infringing_urls` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `url` text NOT NULL,
  `created_at` datetime,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
