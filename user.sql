-- Users Table: Stores user details for login and profiles
CREATE TABLE Users (
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    Username VARCHAR(50) NOT NULL,
    Email VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash VARCHAR(255) NOT NULL,
    MemberSince DATE NOT NULL DEFAULT CURRENT_DATE
);

-- Properties Table: Stores real estate information for predictions
CREATE TABLE Properties (
    PropertyID INT AUTO_INCREMENT PRIMARY KEY,
    Area INT NOT NULL,
    Bathrooms INT NOT NULL,
    Bedrooms INT NOT NULL,
    GuestRoom BOOLEAN NOT NULL,
    Basement BOOLEAN NOT NULL,
    ParkingSpaces INT NOT NULL,
    Price DECIMAL(10, 2) NOT NULL
);

-- Features Table: Optional table to store extended features
CREATE TABLE Features (
    FeatureID INT AUTO_INCREMENT PRIMARY KEY,
    PropertyID INT NOT NULL,
    FeatureName VARCHAR(100),
    FeatureValue VARCHAR(100),
    FOREIGN KEY (PropertyID) REFERENCES Properties(PropertyID)
);

-- Password Reset Table: Stores information for password reset requests
CREATE TABLE PasswordResets (
    ResetID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL,
    ResetToken VARCHAR(255) NOT NULL,
    TokenExpiration DATETIME NOT NULL,
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);
