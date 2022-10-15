package com.example.corespringsecurity.service;


import java.util.List;

import com.example.corespringsecurity.domain.entity.Resources;

public interface ResourcesService {

    Resources getResources(long id);

    List<Resources> getResources();

    void createResources(Resources Resources);

    void deleteResources(long id);
}