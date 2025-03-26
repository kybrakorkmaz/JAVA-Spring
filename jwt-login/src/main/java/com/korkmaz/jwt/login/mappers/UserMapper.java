package com.korkmaz.jwt.login.mappers;


import com.korkmaz.jwt.login.dto.SignUpDto;
import com.korkmaz.jwt.login.dto.UserDto;
import com.korkmaz.jwt.login.entities.User;
import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.NullValuePropertyMappingStrategy;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserDto toUserDto(User user);
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    @Mapping(target = "password", ignore = true)
    User signUpToUser(SignUpDto signUpDto);

}
