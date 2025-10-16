package com.app.mentora.controller.content.pub;

import com.app.mentora.dto.content.ContentResponseDto;
import com.app.mentora.service.content.ContentService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/contents")
public class PublicContentController {

    private final ContentService contentService;

    public PublicContentController(ContentService contentService) {
        this.contentService = contentService;
    }

    @GetMapping("/public")
    public ResponseEntity<List<ContentResponseDto>> getPublicContents() {
        return ResponseEntity.ok(
                contentService.findPublicContents()
                        .stream()
                        .map(ContentResponseDto::from)
                        .toList()
        );
    }

    @GetMapping("/premium")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_PREMIUM')")
    public ResponseEntity<List<ContentResponseDto>> getPremiumContents() {
        return ResponseEntity.ok(
                contentService.findPremiumContents()
                        .stream()
                        .map(ContentResponseDto::from)
                        .toList()
        );
    }

    @GetMapping("/{id}")
    public ResponseEntity<ContentResponseDto> getById(@PathVariable Long id) {
        return ResponseEntity.ok(
                ContentResponseDto.from(contentService.findById(id))
        );
    }
}

