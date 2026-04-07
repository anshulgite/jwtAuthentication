package com.jwtAuthentication.user;

import com.jwtAuthentication.auth.AuthRequest;
import com.jwtAuthentication.common.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserInterface userService;

    public UserController(UserInterface userService) {
        this.userService = userService;
    }

    @PostMapping
    public ApiResponse<UserEntity> saveUser(@RequestBody UserEntity user) {
        try {
            UserEntity userEntity = userService.saveUser(user);
            return ApiResponse.success(userEntity, "User saved successfully");
        }catch (Exception e)
        {
            return ApiResponse.error(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/{username}")
    public ApiResponse<UserEntity> getUser(@PathVariable String username) {
        try {
            UserEntity user = userService.getUser(username);
            if (user != null) {
                return ApiResponse.success(user, "User found successfully");
            } else {
                return ApiResponse.error("User not found", HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            return ApiResponse.error(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/id/{id}")
    public ApiResponse<UserEntity> getUserById(@PathVariable Long id) {
        try {
            UserEntity user = userService.getUserById(id);
            if (user != null) {
                return ApiResponse.success(user, "User found successfully");
            } else {
                return ApiResponse.error("User not found", HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            return ApiResponse.error(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping
    public ApiResponse<java.util.List<UserEntity>> getAllUsers() {
        try {
            java.util.List<UserEntity> users = userService.getAllUsers();
            return ApiResponse.success(users, "Users retrieved successfully");
        } catch (Exception e) {
            return ApiResponse.error(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping
    public ApiResponse<UserEntity> updateUser(@RequestBody UserEntity user) {
        try {
            UserEntity updatedUser = userService.updateUser(user);
            return ApiResponse.success(updatedUser, "User updated successfully");
        } catch (Exception e) {
            return ApiResponse.error(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> deleteUser(@PathVariable Long id) {
        try {
            boolean deleted = userService.deleteUser(id);
            if (deleted) {
                return ApiResponse.success("User deleted successfully");
            } else {
                return ApiResponse.error("Failed to delete user", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (Exception e) {
            return ApiResponse.error(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


}
