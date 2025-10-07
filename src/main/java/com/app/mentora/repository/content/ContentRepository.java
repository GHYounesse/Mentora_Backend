package com.app.mentora.repository.content;

import com.app.mentora.model.content.Content;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ContentRepository extends JpaRepository<Content, Long> {
    List<Content> findByIsPremium(boolean isPremium);
    boolean existsContentByTitle(String title);
    Optional<Content> findById(Long id);
}
