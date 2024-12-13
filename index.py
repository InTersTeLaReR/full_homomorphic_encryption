class UserProfile:
    def __init__(self, name, age, email, interests):
        self.name = name
        self.age = age
        self.email = email
        self.interests = interests
    
    def display_profile(self):
        return {
            "Name": self.name,
            "Age": self.age,
            "Email": self.email,
            "Interests": self.interests
        }

# Example Usage
user = UserProfile("John Doe", 25, "john.doe@example.com", ["Reading", "Traveling", "Coding"])
print(user.display_profile())
