package com.jwtAuthentication.user;

import com.jwtAuthentication.common.Validators;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAspectSupport;

import java.util.Arrays;
import java.util.List;

@Service
public class UserService implements UserInterface {

    Logger logger = LoggerFactory.getLogger(this.getClass());

    private UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

   @Override
   @Transactional
    public UserEntity saveUser(UserEntity user) {
     try {

         Validators.isValidEmail(user.getEmail());
         Validators.isValidPhone(user.getPhone());
         int msgResult = userRepository.checkUserName(user.getUsername());
         if (msgResult>0) {
            throw new RuntimeException("Username already exists");
         }

         user.setPassword(Validators.encodePassword(user.getPassword()));

         UserEntity save = userRepository.save(user);

         return save;
     } catch (Exception e) {
      TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
      logger.error("Error while saving user", e);
      throw new RuntimeException(e.getMessage());
     }
    }

    @Override
    public UserEntity getUser(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public UserEntity getUserById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    @Override
    public List<UserEntity> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    @Transactional
    public UserEntity updateUser(UserEntity user) {
        if( user.getUserId() == null ||user.getUserId()<=0)
            throw new RuntimeException("Invalid user id");
      return   saveUser(user);
    }

    @Override
    @Transactional
    public boolean deleteUser(Long id) {
        if( id == null ||id<=0)
            throw new RuntimeException("Invalid user id");
       if(userRepository.existsById(id))
       {
           userRepository.deleteById(id);
           return true;
       }else
       {
           throw new RuntimeException("user not exist");
       }
    }

}
