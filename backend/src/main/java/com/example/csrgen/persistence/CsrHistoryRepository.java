package com.example.csrgen.persistence;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CsrHistoryRepository extends JpaRepository<CsrHistory, String> {

    List<CsrHistory> findTop40ByOrderByCreatedAtDesc();

    /** Oldest-first — used to trim rows beyond the retention cap. */
    List<CsrHistory> findByOrderByCreatedAtAsc(Pageable pageable);
}
