package com.app.mentora.service.content;

import com.app.mentora.exception.ContentNotFoundException;
import com.app.mentora.exception.DuplicateContentException;
import com.app.mentora.model.content.Content;
import com.app.mentora.repository.content.ContentRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class ContentService {
    private static final Logger log = LoggerFactory.getLogger(ContentService.class);
    final private ContentRepository contentRepository;

    public ContentService(ContentRepository contentRepository) {
        this.contentRepository = contentRepository;
    }


    @Transactional
    public Content create(Content content) {
        if (contentRepository.existsContentByTitle(content.getTitle())) {
            throw new DuplicateContentException("Content title already exists");
        }
        content.setCreatedAt(LocalDateTime.now());
        content.setUpdatedAt(LocalDateTime.now());
        return contentRepository.save(content);
    }


    @Transactional
    public Content update(Long id, Content updated) {
        Content existing = contentRepository.findById(id)
                .orElseThrow(() -> new ContentNotFoundException("Content not found"));

        existing.setTitle(updated.getTitle());
        existing.setBody(updated.getBody());
        existing.setCategory(updated.getCategory());
        existing.setPremium(updated.isPremium());
        existing.setUpdatedAt(LocalDateTime.now());

        return contentRepository.save(existing);
    }


    public void delete(Long id) {
        if (!contentRepository.existsById(id)) {
            throw new ContentNotFoundException("Content with id " + id + " not found");
        }
        contentRepository.deleteById(id);
    }

    public Content findById(Long id) {

        if (contentRepository.findById(id).isPresent()) {
            return contentRepository.findById(id).get();
        } else {
            throw new ContentNotFoundException("Content with id " + id + " not found");
        }
    }

    public List<Content> findAll() {
        return contentRepository.findAll();
    }

    public List<Content> findPublicContents() {
        return contentRepository.findByIsPremium(false);
    }

    public List<Content> findPremiumContents() {
        return contentRepository.findByIsPremium(true);
    }

}
