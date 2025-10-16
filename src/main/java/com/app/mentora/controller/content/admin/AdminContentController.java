package com.app.mentora.controller.content.admin;

import com.app.mentora.dto.content.ContentRequestDto;
import com.app.mentora.dto.content.ContentResponseDto;
import com.app.mentora.model.auth.User;
import com.app.mentora.model.content.Content;
import com.app.mentora.service.auth.CustomUserDetailsService;
import com.app.mentora.service.content.ContentService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/admin/contents")
@PreAuthorize("hasRole('ADMIN')")
public class AdminContentController {
    private static final Logger log = LoggerFactory.getLogger(AdminContentController.class);
    @Autowired
    private ContentService contentService;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    public AdminContentController() {
    }

    @PostMapping
    public ResponseEntity<ContentResponseDto> create(@RequestBody @Valid ContentRequestDto dto, Authentication authentication) {
        log.info("Creating new content with details: {}", dto);
        String email = authentication.getName();

        User user=customUserDetailsService.getUserByEmail(email);
        Content content = contentService.create(dto.toEntity(user));
        log.info("Created new content with details: {}", content);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ContentResponseDto.from(content));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ContentResponseDto> update(
            @PathVariable Long id,
            @RequestBody @Valid ContentRequestDto dto, Authentication authentication) {
        String email = authentication.getName();
        User user=customUserDetailsService.getUserByEmail(email);
        Content updated = contentService.update(id, dto.toEntity(user));
        return ResponseEntity.ok(ContentResponseDto.from(updated));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        contentService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping
    public ResponseEntity<List<ContentResponseDto>> getAll() {
        List<ContentResponseDto> list = contentService.findAll()
                .stream()
                .map(ContentResponseDto::from)
                .toList();
        return ResponseEntity.ok(list);
    }

}
