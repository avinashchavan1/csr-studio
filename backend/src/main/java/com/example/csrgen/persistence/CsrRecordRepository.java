package com.example.csrgen.persistence;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CsrRecordRepository extends JpaRepository<CsrRecord, String> {

    List<CsrRecord> findByOrderByCreatedAtAsc(Pageable pageable);
}
