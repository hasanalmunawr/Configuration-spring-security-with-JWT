package hasanalmunawrDev.jwt.entity;

public enum Role {
    USER,
    ADMIN,
    MANAGER,
    STAFF;

    // Access the role name directly:
    public String getName() {
        return this.name(); // Use enum's built-in name() method
    }
}
