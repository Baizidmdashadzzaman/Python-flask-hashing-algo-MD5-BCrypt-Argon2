-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 16, 2025 at 03:55 PM
-- Server version: 10.4.27-MariaDB
-- PHP Version: 8.2.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `flask_hashing_algo`
--

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `type` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `type`) VALUES
(1, 'Baizid', 'scrypt:32768:8:1$QCjapfyELsswINa7$02c7af651fc57ba2cbf6773cdb0f6e07f393dcdc2b40216e255bc01c0cc651929851528242ad9ca4456d26b996eb225f698779772090e39fcadffdbf798fd87f', 'default'),
(2, 'Baizid1', '904c8cb8773c7ca6bf30ccc225d9986f', 'md5'),
(3, 'Baizid2', '$2b$12$gNXv07aHAbbF54z/SoUPquJOHe.hWKO.h5/1AI3IQAfcf1YT.8wZi', 'bcrypt'),
(4, 'Baizid3', '$2b$12$v6ML6JRNo3oOoJWqpkdfp.OZ7DUc/LTHlufhg2rvgPbysOOv0lJs.', 'bcrypt'),
(5, 'Baizid4', '$argon2id$v=19$m=65536,t=3,p=4$+g6nQiHEnD3fjpdUSc4xxw$0ToeBoz5R8o9OerXQkaHLjyyGGIJKTmsHI3hjFEF6PY', 'argon2');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
