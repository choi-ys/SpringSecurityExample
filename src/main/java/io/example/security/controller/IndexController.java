package io.example.security.controller;

import org.springframework.hateoas.MediaTypes;
import org.springframework.hateoas.RepresentationModel;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.hateoas.IanaLinkRelations.INDEX;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;

@RestController
@RequestMapping(value = "/api/index", produces = MediaTypes.HAL_JSON_VALUE)
public class IndexController {

    @GetMapping
    public RepresentationModel index(){
        RepresentationModel indexRepresentationModel = new RepresentationModel();
        indexRepresentationModel.add(linkTo(IndexController.class).withRel(INDEX));
        return indexRepresentationModel;
    }
}
